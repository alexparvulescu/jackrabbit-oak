/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.jackrabbit.oak.exercise.security.authorization.models.unix;

import static org.apache.jackrabbit.JcrConstants.JCR_MIXINTYPES;

import java.io.IOException;
import java.io.InputStream;
import java.security.Principal;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.annotation.CheckForNull;
import javax.annotation.Nonnull;
import javax.jcr.AccessDeniedException;
import javax.jcr.PathNotFoundException;
import javax.jcr.RepositoryException;
import javax.jcr.UnsupportedRepositoryOperationException;
import javax.jcr.lock.LockException;
import javax.jcr.security.AccessControlException;
import javax.jcr.security.AccessControlManager;
import javax.jcr.security.AccessControlPolicy;
import javax.jcr.security.AccessControlPolicyIterator;
import javax.jcr.version.VersionException;

import org.apache.jackrabbit.api.security.JackrabbitAccessControlPolicy;
import org.apache.jackrabbit.api.security.authorization.PrincipalSetPolicy;
import org.apache.jackrabbit.api.security.principal.PrincipalManager;
import org.apache.jackrabbit.commons.iterator.AccessControlPolicyIteratorAdapter;
import org.apache.jackrabbit.oak.api.CommitFailedException;
import org.apache.jackrabbit.oak.api.PropertyState;
import org.apache.jackrabbit.oak.api.Root;
import org.apache.jackrabbit.oak.api.Tree;
import org.apache.jackrabbit.oak.api.Type;
import org.apache.jackrabbit.oak.commons.PathUtils;
import org.apache.jackrabbit.oak.namepath.NamePathMapper;
import org.apache.jackrabbit.oak.plugins.memory.EmptyNodeState;
import org.apache.jackrabbit.oak.plugins.memory.MemoryNodeStore;
import org.apache.jackrabbit.oak.plugins.name.NamespaceEditorProvider;
import org.apache.jackrabbit.oak.plugins.nodetype.ReadOnlyNodeTypeManager;
import org.apache.jackrabbit.oak.plugins.nodetype.TypeEditorProvider;
import org.apache.jackrabbit.oak.plugins.nodetype.write.NodeTypeRegistry;
import org.apache.jackrabbit.oak.plugins.tree.RootProvider;
import org.apache.jackrabbit.oak.plugins.tree.TreeLocation;
import org.apache.jackrabbit.oak.plugins.tree.TreeType;
import org.apache.jackrabbit.oak.plugins.tree.TreeUtil;
import org.apache.jackrabbit.oak.security.authorization.permission.PermissionValidatorProvider;
import org.apache.jackrabbit.oak.spi.commit.CommitHook;
import org.apache.jackrabbit.oak.spi.commit.CommitInfo;
import org.apache.jackrabbit.oak.spi.commit.CompositeEditorProvider;
import org.apache.jackrabbit.oak.spi.commit.EditorHook;
import org.apache.jackrabbit.oak.spi.commit.MoveTracker;
import org.apache.jackrabbit.oak.spi.commit.PostValidationHook;
import org.apache.jackrabbit.oak.spi.commit.ValidatorProvider;
import org.apache.jackrabbit.oak.spi.lifecycle.RepositoryInitializer;
import org.apache.jackrabbit.oak.spi.nodetype.NodeTypeConstants;
import org.apache.jackrabbit.oak.spi.security.SecurityProvider;
import org.apache.jackrabbit.oak.spi.security.authorization.accesscontrol.AbstractAccessControlManager;
import org.apache.jackrabbit.oak.spi.security.authorization.accesscontrol.PolicyOwner;
import org.apache.jackrabbit.oak.spi.security.authorization.permission.AggregatedPermissionProvider;
import org.apache.jackrabbit.oak.spi.security.authorization.permission.OpenPermissionProvider;
import org.apache.jackrabbit.oak.spi.security.authorization.permission.PermissionConstants;
import org.apache.jackrabbit.oak.spi.security.authorization.permission.PermissionProvider;
import org.apache.jackrabbit.oak.spi.security.authorization.permission.Permissions;
import org.apache.jackrabbit.oak.spi.security.authorization.permission.RepositoryPermission;
import org.apache.jackrabbit.oak.spi.security.authorization.permission.TreePermission;
import org.apache.jackrabbit.oak.spi.security.principal.AdminPrincipal;
import org.apache.jackrabbit.oak.spi.security.principal.PrincipalConfiguration;
import org.apache.jackrabbit.oak.spi.security.principal.PrincipalImpl;
import org.apache.jackrabbit.oak.spi.security.principal.SystemPrincipal;
import org.apache.jackrabbit.oak.spi.security.privilege.PrivilegeBits;
import org.apache.jackrabbit.oak.spi.security.user.UserConfiguration;
import org.apache.jackrabbit.oak.spi.security.user.util.UserUtil;
import org.apache.jackrabbit.oak.spi.state.ApplyDiff;
import org.apache.jackrabbit.oak.spi.state.DefaultNodeStateDiff;
import org.apache.jackrabbit.oak.spi.state.NodeBuilder;
import org.apache.jackrabbit.oak.spi.state.NodeState;
import org.apache.jackrabbit.oak.spi.state.NodeStateUtils;
import org.apache.jackrabbit.oak.spi.state.NodeStore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.collect.Lists;

public class FauxUnixAuthorizationConfiguration extends AbstractAuthorizationConfiguration {

    // TODO
    // - group info in unavailable in hook
    // - group policies not implemented
    // - on user create set default permissions on home via AuthorizableAction
    // - bootstrapping problem with initial content: user info is 'null'
    // - implement 'chown' via policies
    // - implement validator for protection of internal properties
    // - how to enforce admin only commands from the model?

    public static String MIX_REP_FAUX_UNIX = "rep:FauxUnixMixin";
    public static final String REP_USER = "rep:user";
    public static final String REP_PERMISSIONS = "rep:permissions";

    public static final String DEFAULT_PERMISSIONS = "-rw-rw----";

    @Override
    public AccessControlManager getAccessControlManager(Root root, NamePathMapper namePathMapper) {
        return new FauxUnixAccessControlManager(root, namePathMapper, getSecurityProvider());
    }

    @Override
    public PermissionProvider getPermissionProvider(Root root, String workspaceName, Set<Principal> principals) {
        boolean ignore = principals.contains(SystemPrincipal.INSTANCE)
                || principals.stream().anyMatch((p) -> p instanceof AdminPrincipal);
        if (ignore) {
            return OpenPermissionProvider.getInstance();
        }
        return new FauxUnixPermissionProvider(principals);
    }

    @Nonnull
    @Override
    public List<? extends ValidatorProvider> getValidators(@Nonnull String workspaceName,
            @Nonnull Set<Principal> principals, @Nonnull MoveTracker moveTracker) {
        return Collections.singletonList(new PermissionValidatorProvider(getSecurityProvider(), workspaceName,
                principals, moveTracker, getRootProvider(), getTreeProvider()));
    }

    @Nonnull
    @Override
    public List<? extends CommitHook> getCommitHooks(@Nonnull String workspaceName) {
        String adminId = UserUtil
                .getAdminId(getSecurityProvider().getConfiguration(UserConfiguration.class).getParameters());
        return Collections.singletonList(new FauxUnixHook(adminId));
    }

    @Nonnull
    @Override
    public RepositoryInitializer getRepositoryInitializer() {
        return new FauxUnixRepositoryInitializer(getRootProvider());
    }

    private static class FauxUnixAccessControlManager extends AbstractAccessControlManager implements PolicyOwner {

        private static final Logger log = LoggerFactory.getLogger(FauxUnixAccessControlManager.class);

        private final PrincipalManager principalManager;

        protected FauxUnixAccessControlManager(Root root, NamePathMapper namePathMapper,
                SecurityProvider securityProvider) {
            super(root, namePathMapper, securityProvider);
            principalManager = securityProvider.getConfiguration(PrincipalConfiguration.class).getPrincipalManager(root,
                    namePathMapper);
        }

        @Override
        public JackrabbitAccessControlPolicy[] getApplicablePolicies(Principal principal) throws AccessDeniedException,
                AccessControlException, UnsupportedRepositoryOperationException, RepositoryException {
            // editing by 'principal' is not supported
            log.info("getApplicablePolicies({})=<empty>", principal);
            return new JackrabbitAccessControlPolicy[0];
        }

        @Override
        public JackrabbitAccessControlPolicy[] getPolicies(Principal principal) throws AccessDeniedException,
                AccessControlException, UnsupportedRepositoryOperationException, RepositoryException {
            // editing by 'principal' is not supported
            log.info("getPolicies({})=<empty>", principal);
            return new JackrabbitAccessControlPolicy[0];
        }

        @Override
        public AccessControlPolicy[] getEffectivePolicies(Set<Principal> principals) throws AccessDeniedException,
                AccessControlException, UnsupportedRepositoryOperationException, RepositoryException {
            // editing by 'principal' is not supported
            log.info("getEffectivePolicies({})=<empty>", principals);
            return new JackrabbitAccessControlPolicy[0];
        }

        @Override
        public AccessControlPolicy[] getPolicies(String absPath)
                throws PathNotFoundException, AccessDeniedException, RepositoryException {
            UnixPolicy pol = getPolicy(absPath);
            if (pol != null) {
                log.info("getPolicies({})=[{}]", absPath, pol);
                return new AccessControlPolicy[] { pol };
            }
            log.info("getPolicies({})=<empty>", absPath);
            return new AccessControlPolicy[0];
        }

        @CheckForNull
        private UnixPolicy getPolicy(@Nonnull String absPath) throws RepositoryException {
            String oakPath = getOakPath(absPath);
            if (oakPath != null) {
                Tree t = getTree(oakPath, Permissions.NO_PERMISSION, false);
                return new UnixPolicyImpl(t, getNamePathMapper(), principalManager);
            }
            return null;
        }

        @Override
        public AccessControlPolicy[] getEffectivePolicies(String absPath)
                throws PathNotFoundException, AccessDeniedException, RepositoryException {
            UnixPolicy pol = getPolicy(absPath);
            if (pol != null) {
                log.info("getEffectivePolicies({})=[{}]", absPath, pol);
                return new AccessControlPolicy[] { pol };
            }
            log.info("getEffectivePolicies({})=<empty>", absPath);
            return new AccessControlPolicy[0];
        }

        @Override
        public AccessControlPolicyIterator getApplicablePolicies(String absPath)
                throws PathNotFoundException, AccessDeniedException, RepositoryException {
            UnixPolicy pol = getPolicy(absPath);
            if (pol != null) {
                log.info("getApplicablePolicies({})=<{}>", absPath, pol);
                return new AccessControlPolicyIteratorAdapter(Collections.singleton(pol));
            }
            log.info("getApplicablePolicies({})=<empty>", absPath);
            return AccessControlPolicyIteratorAdapter.EMPTY;
        }

        @Override
        public void setPolicy(String absPath, AccessControlPolicy policy) throws PathNotFoundException,
                AccessControlException, AccessDeniedException, LockException, VersionException, RepositoryException {
            // TODO consider setting the mixin here
            throw new AccessControlException("set not supported");
        }

        @Override
        public void removePolicy(String absPath, AccessControlPolicy policy) throws PathNotFoundException,
                AccessControlException, AccessDeniedException, LockException, VersionException, RepositoryException {
            throw new AccessControlException("remove not supported");
        }

        @Override
        public boolean defines(String absPath, AccessControlPolicy acp) {
            return acp instanceof UnixPolicy;
        }
    }

    private static interface UnixPolicy extends PrincipalSetPolicy, JackrabbitAccessControlPolicy {
    }

    private static class UnixPolicyImpl implements UnixPolicy {

        private final String oakPath;

        private final Principal principal;

        private final NamePathMapper namePathMapper;

        private final PrincipalManager principalManager;

        public UnixPolicyImpl(@Nonnull Tree tree, @Nonnull NamePathMapper namePathMapper,
                PrincipalManager principalManager) {
            this.oakPath = tree.getPath();
            this.namePathMapper = namePathMapper;
            this.principalManager = principalManager;

            // TODO group, other
            String u = TreeUtil.getString(tree, REP_USER);
            this.principal = asPrincipal(u);
        }

        private Principal asPrincipal(String principalName) {
            Principal principal = principalManager.getPrincipal(principalName);
            if (principal == null) {
                principal = new PrincipalImpl(principalName);
            }
            return principal;
        }

        @Override
        public Set<Principal> getPrincipals() {
            return Collections.singleton(principal);
        }

        @Override
        public boolean addPrincipals(Principal... principals) throws AccessControlException {
            throw new AccessControlException("add not supported");
        }

        @Override
        public boolean removePrincipals(Principal... principals) throws AccessControlException {
            throw new AccessControlException("remove not supported");
        }

        @Override
        public String getPath() {
            return namePathMapper.getJcrPath(oakPath);
        }

        @Override
        public String toString() {
            return "UnixPolicyImpl [oakPath=" + oakPath + ", principal=" + principal.getName() + "]";
        }
    }

    // ------

    private static class FauxUnixPermissionProvider implements AggregatedPermissionProvider {

        private static final Logger log = LoggerFactory.getLogger(FauxUnixPermissionProvider.class);

        private final Set<Principal> principals;

        public FauxUnixPermissionProvider(@Nonnull Set<Principal> principals) {
            this.principals = Collections.unmodifiableSet(principals);
        }

        @Override
        public void refresh() {
            log.info("refresh");
        }

        @Override
        public Set<String> getPrivileges(Tree tree) {
            // TODO
            log.info("getPrivileges ({})", tree.getPath());
            throw new RuntimeException("not supported");
        }

        @Override
        public RepositoryPermission getRepositoryPermission() {
            log.info("getRepositoryPermission=EMPTY");
            return RepositoryPermission.EMPTY;
        }

        @Override
        public TreePermission getTreePermission(Tree tree, TreePermission parentPermission) {
            TreePermission p = new FauxUnixPermission(tree, asNames(principals));
            log.info("getTreePermission ({}, {})={}", tree.getPath(), parentPermission, p);
            return p;
        }

        @Override
        public TreePermission getTreePermission(Tree tree, TreeType type, TreePermission parentPermission) {
            TreePermission p = new FauxUnixPermission(tree, asNames(principals));
            log.info("getTreePermission ({}, {}, {})={}", tree.getPath(), type, parentPermission, p);
            return p;
        }

        @Override
        public boolean hasPrivileges(Tree tree, String... privilegeNames) {
            // TODO
            log.info("getPrivileges ({}, {})", tree.getPath(), Arrays.toString(privilegeNames));
            throw new RuntimeException("not supported");
        }

        @Override
        public boolean isGranted(Tree tree, PropertyState property, long permissions) {
            // TODO
            log.info("isGranted ({}, {}, {})", tree.getPath(), property, permissions);
            throw new RuntimeException("not supported");
        }

        @Override
        public boolean isGranted(String oakPath, String jcrActions) {
            // TODO
            log.info("isGranted ({}, {})", oakPath, jcrActions);
            throw new RuntimeException("not supported");
        }

        @Override
        public boolean isGranted(TreeLocation location, long permissions) {
            // TODO
            log.info("isGranted ({}, {})", location, permissions);
            throw new RuntimeException("not supported");
        }

        @Override
        public PrivilegeBits supportedPrivileges(Tree tree, PrivilegeBits privilegeBits) {
            // TODO
            log.info("supportedPrivileges ({}, {})", tree.getPath(), privilegeBits);
            throw new RuntimeException("not supported");
        }

        @Override
        public long supportedPermissions(Tree tree, PropertyState property, long permissions) {
            // TODO
            log.info("supportedPermissions ({}, {}, {})", tree.getPath(), property, permissions);
            throw new RuntimeException("not supported");
        }

        @Override
        public long supportedPermissions(TreeLocation location, long permissions) {
            long supported = permissions & Permissions.READ;
            if (supported != Permissions.NO_PERMISSION) {
                log.info("supportedPermissions ({}, {})={}", location, permissions, supported);
                return supported;
            } else {
                log.info("supportedPermissions ({}, {})=NO_PERMISSION", location, permissions);
                return Permissions.NO_PERMISSION;
            }
        }

        @Override
        public long supportedPermissions(TreePermission treePermission, PropertyState property, long permissions) {
            long supported = permissions & Permissions.READ;
            if (supported != Permissions.NO_PERMISSION && (treePermission instanceof FauxUnixPermission)) {
                log.info("supportedPermissions ({}, {}, {})={}", treePermission, property, permissions, supported);
                return supported;
            } else {
                log.info("supportedPermissions ({}, {}, {})=NO_PERMISSION", treePermission, property, permissions);
                return Permissions.NO_PERMISSION;
            }
        }
    }

    private static Set<String> asNames(Set<Principal> principals) {
        Set<String> ps = new HashSet<>();
        for (Principal p : principals) {
            ps.add(p.getName());
        }
        return ps;
    }

    private static final class FauxUnixPermission implements TreePermission {

        private static final Logger log = LoggerFactory.getLogger(FauxUnixPermission.class);

        private final Tree tree;

        private final Set<String> principals;

        public FauxUnixPermission(Tree tree, Set<String> principals) {
            this.tree = tree;
            this.principals = principals;
        }

        @Override
        public TreePermission getChildPermission(String childName, NodeState childState) {
            TreePermission t = new FauxUnixPermission(tree.getChild(childName), principals);
            log.info("getChildPermission ({}, {})={}", tree.getPath(), childName, t);
            return t;
        }

        @Override
        public boolean canReadAll() {
            log.info("canReadAll({})=false", tree.getPath());
            return false;
        }

        @Override
        public boolean canRead() {
            boolean r = isAllow(true);
            log.info("canRead({})={}", tree.getPath(), r);
            return r;
        }

        @Override
        public boolean canReadProperties() {
            boolean r = isAllow(true);
            log.info("canReadProperties({})={}", tree.getPath(), r);
            return r;
        }

        @Override
        public boolean canRead(PropertyState property) {
            boolean r = isAllow(true);
            log.info("canRead({}, {})={}", tree.getPath(), property.getName(), r);
            return r;
        }

        @Override
        public boolean isGranted(long permissions) {
            if (Permissions.includes(Permissions.READ, permissions)) {
                boolean r = isAllow(true);
                log.info("isGranted({}, READ)={}", tree.getPath(), r);
                return r;
            }

            if (Permissions.includes(Permissions.WRITE, permissions)) {
                boolean r = isAllow(false);
                log.info("isGranted({}, WRITE)={}", tree.getPath(), r);
                return r;
            }

            log.info("isGranted({}, {})=false", tree.getPath(), Permissions.getNames(permissions));
            return false;
        }

        @Override
        public boolean isGranted(long permissions, PropertyState property) {
            return isGranted(permissions);
        }

        private boolean isAllow(boolean read) {
            // open certain paths up for 'read' access by default
            for (String p : PermissionConstants.DEFAULT_READ_PATHS) {
                if (PathUtils.isAncestor(p, tree.getPath())) {
                    return true;
                }
            }

            Tree t = tree;
            String u = TreeUtil.getString(t, REP_USER);
            // transient space items don't have the user info, so we'll fallback
            // to parent info
            while (u == null && !t.isRoot()) {
                t = t.getParent();
                u = TreeUtil.getString(t, REP_USER);
            }

            String perms = TreeUtil.getString(t, REP_PERMISSIONS);
            if (perms == null) {
                return false;
            }

            // user
            if (principals.contains(u) && (read && perms.charAt(1) == 'r' || perms.charAt(2) == 'w')) {
                return true;
            }

            // TODO group check

            // everyone check
            if (read && perms.charAt(7) == 'r' || perms.charAt(8) == 'w') {
                return true;
            }
            return false;
        }

        @Override
        public String toString() {
            return "FauxUnixPermission [path=" + tree.getPath() + ", principals=" + principals + "]";
        }
    }

    private static class FauxUnixHook implements PostValidationHook {

        private final String adminId;

        public FauxUnixHook(String adminId) {
            this.adminId = adminId;
        }

        @Override
        public NodeState processCommit(NodeState before, NodeState after, CommitInfo info)
                throws CommitFailedException {
            // TODO convert CommitInfo.OAK_UNKNOWN into admin?
            String userId = info.getUserId();

            if (userId == null || CommitInfo.OAK_UNKNOWN.equals(userId)) {
                userId = adminId;
            }

            return FauxUnixHookDiff.apply(before, after, userId);
        }
    }

    private static class FauxUnixHookDiff extends DefaultNodeStateDiff {

        private final NodeBuilder builder;
        private final String userId;

        private FauxUnixHookDiff(NodeBuilder builder, String userId) {
            this.builder = builder;
            this.userId = userId;
        }

        static NodeState apply(NodeState before, NodeState after, String userId) {
            NodeBuilder builder = after.builder();
            after.compareAgainstBaseState(before, new FauxUnixHookDiff(builder, userId));
            return builder.getNodeState();
        }

        @Override
        public boolean childNodeAdded(String name, NodeState after) {
            if (NodeStateUtils.isHidden(name)) {
                return true;
            }
            NodeBuilder b = builder.getChildNode(name);
            b.setProperty(FauxUnixAuthorizationConfiguration.REP_USER, userId);
            b.setProperty(FauxUnixAuthorizationConfiguration.REP_PERMISSIONS,
                    FauxUnixAuthorizationConfiguration.DEFAULT_PERMISSIONS);
            List<String> mixins = Lists.newArrayList(after.getNames(JCR_MIXINTYPES));
            mixins.add(MIX_REP_FAUX_UNIX);
            b.setProperty(JCR_MIXINTYPES, mixins, Type.NAMES);

            return EmptyNodeState.compareAgainstEmptyState(after, new FauxUnixHookDiff(b, userId));
        }

        @Override
        public boolean childNodeChanged(String name, NodeState before, NodeState after) {
            if (NodeStateUtils.isHidden(name)) {
                return true;
            }
            return after.compareAgainstBaseState(before, new FauxUnixHookDiff(builder.getChildNode(name), userId));
        }
    }

    private static class FauxUnixRepositoryInitializer implements RepositoryInitializer {

        private static final Logger log = LoggerFactory.getLogger(FauxUnixRepositoryInitializer.class);

        private final RootProvider rootProvider;

        public FauxUnixRepositoryInitializer(RootProvider rootProvider) {
            this.rootProvider = rootProvider;
        }

        @Override
        public void initialize(NodeBuilder builder) {
            NodeState base = builder.getNodeState();
            NodeStore store = new MemoryNodeStore(base);

            // TODO inject FauxUnixHook
            Root root = rootProvider.createSystemRoot(store, new EditorHook(
                    new CompositeEditorProvider(new NamespaceEditorProvider(), new TypeEditorProvider())));
            if (registerNodeTypes(root)) {
                log.info("installed required node types");
                NodeState target = store.getRoot();
                target.compareAgainstBaseState(base, new ApplyDiff(builder));
            }
        }

        static boolean registerNodeTypes(@Nonnull final Root root) {
            try {
                ReadOnlyNodeTypeManager ntMgr = new ReadOnlyNodeTypeManager() {
                    @Override
                    protected Tree getTypes() {
                        return root.getTree(NodeTypeConstants.NODE_TYPES_PATH);
                    }
                };
                if (!ntMgr.hasNodeType(MIX_REP_FAUX_UNIX)) {
                    try (InputStream stream = FauxUnixAuthorizationConfiguration.class
                            .getResourceAsStream("fauxunix_nodetypes.cnd")) {
                        NodeTypeRegistry.register(root, stream, "FauxUnix types");
                        return true;
                    }
                }
            } catch (IOException | RepositoryException e) {
                throw new IllegalStateException("Unable to read FauxUnix node types", e);
            }
            return false;
        }
    }
}
