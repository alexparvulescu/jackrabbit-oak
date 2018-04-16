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
import static org.apache.jackrabbit.oak.exercise.security.authorization.models.unix.FauxUnixAuthorizationHelper.isAdmin;
import static org.apache.jackrabbit.oak.spi.security.RegistrationConstants.OAK_SECURITY_NAME;

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
import javax.annotation.Nullable;
import javax.jcr.AccessDeniedException;
import javax.jcr.PathNotFoundException;
import javax.jcr.RepositoryException;
import javax.jcr.UnsupportedRepositoryOperationException;
import javax.jcr.lock.LockException;
import javax.jcr.security.AccessControlException;
import javax.jcr.security.AccessControlManager;
import javax.jcr.security.AccessControlPolicy;
import javax.jcr.security.AccessControlPolicyIterator;
import javax.jcr.security.Privilege;
import javax.jcr.version.VersionException;

import org.apache.jackrabbit.api.security.JackrabbitAccessControlPolicy;
import org.apache.jackrabbit.commons.iterator.AccessControlPolicyIteratorAdapter;
import org.apache.jackrabbit.oak.api.AuthInfo;
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
import org.apache.jackrabbit.oak.spi.commit.CompositeHook;
import org.apache.jackrabbit.oak.spi.commit.EditorHook;
import org.apache.jackrabbit.oak.spi.commit.MoveTracker;
import org.apache.jackrabbit.oak.spi.commit.PostValidationHook;
import org.apache.jackrabbit.oak.spi.commit.ValidatorProvider;
import org.apache.jackrabbit.oak.spi.lifecycle.RepositoryInitializer;
import org.apache.jackrabbit.oak.spi.nodetype.NodeTypeConstants;
import org.apache.jackrabbit.oak.spi.security.ConfigurationBase;
import org.apache.jackrabbit.oak.spi.security.SecurityConfiguration;
import org.apache.jackrabbit.oak.spi.security.SecurityProvider;
import org.apache.jackrabbit.oak.spi.security.authorization.AuthorizationConfiguration;
import org.apache.jackrabbit.oak.spi.security.authorization.accesscontrol.AbstractAccessControlManager;
import org.apache.jackrabbit.oak.spi.security.authorization.accesscontrol.PolicyOwner;
import org.apache.jackrabbit.oak.spi.security.authorization.permission.AggregatedPermissionProvider;
import org.apache.jackrabbit.oak.spi.security.authorization.permission.OpenPermissionProvider;
import org.apache.jackrabbit.oak.spi.security.authorization.permission.PermissionConstants;
import org.apache.jackrabbit.oak.spi.security.authorization.permission.PermissionProvider;
import org.apache.jackrabbit.oak.spi.security.authorization.permission.Permissions;
import org.apache.jackrabbit.oak.spi.security.authorization.permission.RepositoryPermission;
import org.apache.jackrabbit.oak.spi.security.authorization.permission.TreePermission;
import org.apache.jackrabbit.oak.spi.security.authorization.restriction.RestrictionProvider;
import org.apache.jackrabbit.oak.spi.security.privilege.PrivilegeBits;
import org.apache.jackrabbit.oak.spi.security.privilege.PrivilegeConstants;
import org.apache.jackrabbit.oak.spi.security.user.UserConfiguration;
import org.apache.jackrabbit.oak.spi.security.user.util.UserUtil;
import org.apache.jackrabbit.oak.spi.state.ApplyDiff;
import org.apache.jackrabbit.oak.spi.state.DefaultNodeStateDiff;
import org.apache.jackrabbit.oak.spi.state.NodeBuilder;
import org.apache.jackrabbit.oak.spi.state.NodeState;
import org.apache.jackrabbit.oak.spi.state.NodeStateUtils;
import org.apache.jackrabbit.oak.spi.state.NodeStore;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.ConfigurationPolicy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Supplier;
import com.google.common.base.Suppliers;
import com.google.common.collect.Sets;

@Component(service = { AuthorizationConfiguration.class,
        SecurityConfiguration.class }, immediate = true, configurationPolicy = ConfigurationPolicy.REQUIRE, property = OAK_SECURITY_NAME
                + "=org.apache.jackrabbit.oak.exercise.security.authorization.models.unix.FauxUnixAuthorizationConfiguration")
public class FauxUnixAuthorizationConfiguration extends ConfigurationBase implements AuthorizationConfiguration {

    // TODO
    // - group info is unavailable in hook
    // - group policies not implemented
    //
    // - what kind of rights do I need to run chmod?
    // - does chown check if the new owner exists?
    //
    // - implement validator to protect internal properties
    //
    // - bootstrapping problem with initial content: user info is 'null'

    public static String MIX_REP_FAUX_UNIX = "rep:FauxUnixMixin";
    static final String REP_USER = "rep:user";
    static final String REP_GROUP = "rep:group";
    static final String REP_PERMISSIONS = "rep:permissions";

    static final String DEFAULT_PERMISSIONS = "-rw-r-----";

    @Override
    public AccessControlManager getAccessControlManager(Root root, NamePathMapper namePathMapper) {
        return new FauxUnixAccessControlManager(root, namePathMapper, getSecurityProvider());
    }

    @Override
    public PermissionProvider getPermissionProvider(Root root, String workspaceName, Set<Principal> principals) {
        if (isAdmin(principals)) {
            return OpenPermissionProvider.getInstance();
        }
        return new FauxUnixPermissionProvider(principals);
    }

    @Nonnull
    @Override
    public List<? extends ValidatorProvider> getValidators(@Nonnull String workspaceName,
            @Nonnull Set<Principal> principals, @Nonnull MoveTracker moveTracker) {

        // TODO reverify
        PermissionValidatorProvider pvp = new PermissionValidatorProvider(getSecurityProvider(), workspaceName,
                principals, moveTracker, getRootProvider(), getTreeProvider());

        return Collections.singletonList(pvp);
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
        String adminId = UserUtil
                .getAdminId(getSecurityProvider().getConfiguration(UserConfiguration.class).getParameters());
        return new FauxUnixRepositoryInitializer(getRootProvider(), adminId);
    }

    @Nonnull
    @Override
    public RestrictionProvider getRestrictionProvider() {
        return RestrictionProvider.EMPTY;
    }

    private static class FauxUnixAccessControlManager extends AbstractAccessControlManager implements PolicyOwner {

        private static final Logger log = LoggerFactory.getLogger(FauxUnixAccessControlManager.class);

        protected FauxUnixAccessControlManager(Root root, NamePathMapper namePathMapper,
                SecurityProvider securityProvider) {
            super(root, namePathMapper, securityProvider);
        }

        @Nonnull
        @Override
        public Privilege[] getSupportedPrivileges(@Nullable String absPath) throws RepositoryException {
            return new Privilege[] { privilegeFromName(PrivilegeConstants.JCR_READ),
                    privilegeFromName(PrivilegeConstants.JCR_WRITE) };
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
            FauxUnixPolicy pol = getPolicy(absPath);
            if (pol != null) {
                log.info("getPolicies({})=[{}]", absPath, pol);
                return new AccessControlPolicy[] { pol };
            }
            log.info("getPolicies({})=<empty>", absPath);
            return new AccessControlPolicy[0];
        }

        @CheckForNull
        private FauxUnixPolicy getPolicy(@Nonnull String absPath) throws RepositoryException {
            String oakPath = getOakPath(absPath);
            if (oakPath != null) {
                Tree t = getTree(oakPath, Permissions.READ, false);
                if (t == null) {
                    return null;
                }
                return new FauxUnixPolicyImpl(t, getNamePathMapper());
            }
            return null;
        }

        @Override
        public AccessControlPolicy[] getEffectivePolicies(String absPath)
                throws PathNotFoundException, AccessDeniedException, RepositoryException {
            FauxUnixPolicy pol = getPolicy(absPath);
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
            FauxUnixPolicy pol = getPolicy(absPath);
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
            if (!(policy instanceof FauxUnixPolicyImpl)) {
                throw new AccessControlException("Unsupported policy implementation: " + policy);
            }
            FauxUnixPolicyImpl fup = (FauxUnixPolicyImpl) policy;
            if (!fup.isDirty()) {
                return;
            }

            if (!fup.getPath().equals(absPath)) {
                throw new AccessControlException("Path mismatch: Expected " + fup.getPath() + ", Found: " + absPath);
            }

            String oakPath = getOakPath(absPath);
            // TODO what kind of rights do I need to run chmod?
            Tree t = getTree(oakPath, Permissions.WRITE, false);
            String o = TreeUtil.getString(t, REP_USER);
            AuthInfo authInfo = getRoot().getContentSession().getAuthInfo();
            if (!authInfo.getUserID().equals(o) && !isAdmin(authInfo.getPrincipals())) {
                throw new AccessControlException("Unsupported path: " + absPath);
            }

            Tree typeRoot = getRoot().getTree(NodeTypeConstants.NODE_TYPES_PATH);
            if (!TreeUtil.isNodeType(t, MIX_REP_FAUX_UNIX, typeRoot)) {
                TreeUtil.addMixin(t, MIX_REP_FAUX_UNIX, typeRoot, null);
            }
            t.setProperty(REP_USER, fup.getOwner());
            t.setProperty(REP_GROUP, fup.getGroups(), Type.STRINGS);
            t.setProperty(REP_PERMISSIONS, fup.getPermissions());
            log.info("setPolicy ({})={}", oakPath, fup);
        }

        @Override
        public void removePolicy(String absPath, AccessControlPolicy policy) throws PathNotFoundException,
                AccessControlException, AccessDeniedException, LockException, VersionException, RepositoryException {
            throw new AccessControlException("remove not supported");
        }

        @Override
        public boolean defines(String absPath, AccessControlPolicy acp) {
            return acp instanceof FauxUnixPolicy;
        }
    }

    public static interface FauxUnixPolicy extends JackrabbitAccessControlPolicy {

        String getOwner();

        Set<String> getGroups();

        String getPermissions();
    }

    static class FauxUnixPolicyImpl implements FauxUnixPolicy {

        private final String oakPath;

        private final NamePathMapper namePathMapper;

        private String owner;

        private Set<String> groups;

        private char[] permissions = DEFAULT_PERMISSIONS.toCharArray();

        private boolean isDirty = false;

        public FauxUnixPolicyImpl(@Nonnull Tree tree, @Nonnull NamePathMapper namePathMapper) {
            this.oakPath = tree.getPath();
            this.namePathMapper = namePathMapper;
            this.owner = TreeUtil.getString(tree, REP_USER);
            this.groups = FauxUnixAuthorizationHelper.getGroupsOrEmpty(tree);
            String perms = TreeUtil.getString(tree, REP_PERMISSIONS);
            if (perms != null && perms.length() == 10) {
                this.permissions = perms.toCharArray();
            }
        }

        @Override
        public String getOwner() {
            return owner;
        }

        @Override
        public Set<String> getGroups() {
            return groups;
        }

        @Override
        public String getPermissions() {
            return String.valueOf(permissions);
        }

        boolean isDirty() {
            return isDirty;
        }

        @Override
        public String getPath() {
            return namePathMapper.getJcrPath(oakPath);
        }

        @Override
        public String toString() {
            return "UnixPolicyImpl [path=" + oakPath + ", principal=" + getOwner() + ", groups=" + getGroups()
                    + ",permissions=" + getPermissions() + "]";
        }

        public void setOwner(String principal) {
            // TODO does chown check if the new owner exists?
            this.owner = principal;
            isDirty = true;
        }

        public void setGroups(Set<String> groups) {
            this.groups = groups;
            isDirty = true;
        }

        public void setPermissions(String flags) throws AccessControlException {
            if (flags.length() != 5) {
                throw new AccessControlException("unexpected flags value. expecting: u=rwx OR g=rwx OR o=rwx OR a=rwx");
            }
            char[] farr = flags.toCharArray();
            boolean isU = farr[0] == 'u';
            boolean isG = farr[0] == 'g';
            boolean isO = farr[0] == 'o';
            boolean isA = farr[0] == 'a';
            boolean isR = farr[2] == 'r';
            boolean isW = farr[3] == 'w';
            boolean isX = farr[4] == 'x';

            if (isU || isA) {
                permissions[1] = isR ? 'r' : '-';
                permissions[2] = isW ? 'w' : '-';
                permissions[3] = isX ? 'x' : '-';
            }
            if (isG || isA) {
                permissions[4] = isR ? 'r' : '-';
                permissions[5] = isW ? 'w' : '-';
                permissions[6] = isX ? 'x' : '-';
            }
            if (isO || isA) {
                permissions[7] = isR ? 'r' : '-';
                permissions[8] = isW ? 'w' : '-';
                permissions[9] = isX ? 'x' : '-';
            }
            isDirty = true;
        }
    }

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
            log.info("getPrivileges({})", tree.getPath());
            throw new RuntimeException("not supported");
        }

        @Override
        public RepositoryPermission getRepositoryPermission() {
            log.info("getRepositoryPermission=EMPTY");
            return RepositoryPermission.EMPTY;
        }

        @Override
        public TreePermission getTreePermission(Tree tree, TreePermission parentPermission) {
            TreePermission p = new FauxUnixPermission(tree, FauxUnixAuthorizationHelper.asNames(principals));
            log.info("getTreePermission({}, {})={}", tree.getPath(), parentPermission, p);
            return p;
        }

        @Override
        public TreePermission getTreePermission(Tree tree, TreeType type, TreePermission parentPermission) {
            TreePermission p = new FauxUnixPermission(tree, FauxUnixAuthorizationHelper.asNames(principals));
            log.info("getTreePermission({}, {}, {})={}", tree.getPath(), type, parentPermission, p);
            return p;
        }

        @Override
        public boolean hasPrivileges(Tree tree, String... privilegeNames) {
            // TODO
            log.info("getPrivileges({}, {})", tree.getPath(), Arrays.toString(privilegeNames));
            throw new RuntimeException("not supported");
        }

        @Override
        public boolean isGranted(Tree tree, PropertyState property, long permissions) {
            TreePermission p = new FauxUnixPermission(tree, FauxUnixAuthorizationHelper.asNames(principals));
            boolean is = p.isGranted(permissions, property);
            log.info("isGranted({}, {}, {})={}", tree.getPath(), property, Permissions.getNames(permissions), is);
            return is;
        }

        @Override
        public boolean isGranted(String oakPath, String jcrActions) {
            // TODO
            log.info("isGranted({}, {})", oakPath, jcrActions);
            throw new RuntimeException("not supported");
        }

        @Override
        public boolean isGranted(TreeLocation location, long permissions) {
            // TODO
            log.info("isGranted({}, {})", location, permissions);
            throw new RuntimeException("not supported");
        }

        @Override
        public PrivilegeBits supportedPrivileges(Tree tree, PrivilegeBits privilegeBits) {
            // TODO
            log.info("supportedPrivileges({}, {})", tree.getPath(), privilegeBits);
            throw new RuntimeException("not supported");
        }

        @Override
        public long supportedPermissions(Tree tree, PropertyState property, long permissions) {
            // TODO
            log.info("supportedPermissions({}, {}, {})", tree.getPath(), property, permissions);
            throw new RuntimeException("not supported");
        }

        @Override
        public long supportedPermissions(TreeLocation location, long permissions) {
            long supported = permissions & Permissions.READ;
            if (supported != Permissions.NO_PERMISSION) {
                log.info("supportedPermissions({}, {})={}", location, permissions, supported);
                return supported;
            } else {
                log.info("supportedPermissions({}, {})=NO_PERMISSION", location, permissions);
                return Permissions.NO_PERMISSION;
            }
        }

        @Override
        public long supportedPermissions(TreePermission treePermission, PropertyState property, long permissions) {
            long supported = permissions & Permissions.READ;
            if (supported != Permissions.NO_PERMISSION && (treePermission instanceof FauxUnixPermission)) {
                log.info("supportedPermissions({}, {}, {})={}", treePermission, property, permissions, supported);
                return supported;
            } else {
                log.info("supportedPermissions({}, {}, {})=NO_PERMISSION", treePermission, property, permissions);
                return Permissions.NO_PERMISSION;
            }
        }
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
            log.info("getChildPermission({}, {})={}", tree.getPath(), childName, t);
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
            if (read) {
                for (String p : PermissionConstants.DEFAULT_READ_PATHS) {
                    if (PathUtils.isAncestor(p, tree.getPath())) {
                        return true;
                    }
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

            // group
            Set<String> groups = FauxUnixAuthorizationHelper.getGroupsOrEmpty(t);
            boolean hasGroup = !Sets.intersection(principals, groups).isEmpty();
            if (hasGroup && (read && perms.charAt(4) == 'r' || perms.charAt(8) == '5')) {
                return true;
            }

            // other
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

        private static final Logger log = LoggerFactory.getLogger(FauxUnixHook.class);
        private final String adminId;

        public FauxUnixHook(String adminId) {
            this.adminId = adminId;
        }

        @Override
        public NodeState processCommit(NodeState before, NodeState after, CommitInfo info)
                throws CommitFailedException {
            String userId = info.getUserId();
            if (userId == null || CommitInfo.OAK_UNKNOWN.equals(userId)) {
                userId = adminId;
            }
            // TODO group info
            Supplier<Set<String>> groups;
            if (info.getInfo().containsKey("SESSION_PRINCIPALS")) {
                @SuppressWarnings("unchecked")
                Set<Principal> principals = (Set<Principal>) info.getInfo().get("SESSION_PRINCIPALS");
                groups = Suppliers.ofInstance(FauxUnixAuthorizationHelper.asNames(principals));
                log.info("principals for {}={}", userId, groups);
            } else {
                groups = Suppliers.ofInstance(new HashSet<>());
            }
            return FauxUnixHookDiff.apply(before, after, userId, groups);
        }
    }

    private static class FauxUnixHookDiff extends DefaultNodeStateDiff {

        private final NodeBuilder builder;
        private final String userId;
        private final Supplier<Set<String>> groups;

        private FauxUnixHookDiff(NodeBuilder builder, String userId, Supplier<Set<String>> groups) {
            this.builder = builder;
            this.userId = userId;
            this.groups = groups;
        }

        static NodeState apply(NodeState before, NodeState after, String userId, Supplier<Set<String>> groups) {
            NodeBuilder builder = after.builder();
            after.compareAgainstBaseState(before, new FauxUnixHookDiff(builder, userId, groups));
            return builder.getNodeState();
        }

        @Override
        public boolean childNodeAdded(String name, NodeState after) {
            if (NodeStateUtils.isHidden(name)) {
                return true;
            }
            NodeBuilder b = builder.getChildNode(name);
            if (!b.hasProperty(REP_USER)) {
                b.setProperty(REP_USER, userId);
            }
            if (!b.hasProperty(REP_GROUP)) {
                // TODO clean group membership to remove 'everyone' and self.
                Set<String> group = groups.get();
                group.remove("everyone");
                group.remove(userId);
                b.setProperty(REP_GROUP, groups.get(), Type.STRINGS);
            }
            b.setProperty(REP_PERMISSIONS, DEFAULT_PERMISSIONS);
            Set<String> mixins = Sets.newHashSet(after.getNames(JCR_MIXINTYPES));
            mixins.add(MIX_REP_FAUX_UNIX);
            b.setProperty(JCR_MIXINTYPES, mixins, Type.NAMES);

            return EmptyNodeState.compareAgainstEmptyState(after, new FauxUnixHookDiff(b, userId, groups));
        }

        @Override
        public boolean childNodeChanged(String name, NodeState before, NodeState after) {
            if (NodeStateUtils.isHidden(name)) {
                return true;
            }
            return after.compareAgainstBaseState(before,
                    new FauxUnixHookDiff(builder.getChildNode(name), userId, groups));
        }
    }

    private static class FauxUnixRepositoryInitializer implements RepositoryInitializer {

        private static final Logger log = LoggerFactory.getLogger(FauxUnixRepositoryInitializer.class);

        private final RootProvider rootProvider;

        private final String adminId;

        public FauxUnixRepositoryInitializer(RootProvider rootProvider, String adminId) {
            this.rootProvider = rootProvider;
            this.adminId = adminId;
        }

        @Override
        public void initialize(NodeBuilder builder) {
            NodeState base = builder.getNodeState();
            NodeStore store = new MemoryNodeStore(base);
            CommitHook hook = new CompositeHook(
                    new EditorHook(new CompositeEditorProvider(new NamespaceEditorProvider(), new TypeEditorProvider()))
            /* ,new FauxUnixHook(adminId) */ );
            Root root = rootProvider.createSystemRoot(store, hook);
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
