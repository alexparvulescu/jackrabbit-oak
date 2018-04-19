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
import static org.apache.jackrabbit.oak.exercise.security.authorization.models.unix.FauxUnixAuthorizationHelper.asNames;
import static org.apache.jackrabbit.oak.exercise.security.authorization.models.unix.FauxUnixAuthorizationHelper.getGroupsOrEmpty;
import static org.apache.jackrabbit.oak.exercise.security.authorization.models.unix.FauxUnixAuthorizationHelper.getPath;
import static org.apache.jackrabbit.oak.exercise.security.authorization.models.unix.FauxUnixAuthorizationHelper.getPropertyName;
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

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.jcr.RepositoryException;
import javax.jcr.security.AccessControlManager;

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
import org.apache.jackrabbit.oak.spi.security.authorization.AuthorizationConfiguration;
import org.apache.jackrabbit.oak.spi.security.authorization.permission.AggregatedPermissionProvider;
import org.apache.jackrabbit.oak.spi.security.authorization.permission.OpenPermissionProvider;
import org.apache.jackrabbit.oak.spi.security.authorization.permission.PermissionConstants;
import org.apache.jackrabbit.oak.spi.security.authorization.permission.PermissionProvider;
import org.apache.jackrabbit.oak.spi.security.authorization.permission.Permissions;
import org.apache.jackrabbit.oak.spi.security.authorization.permission.RepositoryPermission;
import org.apache.jackrabbit.oak.spi.security.authorization.permission.TreePermission;
import org.apache.jackrabbit.oak.spi.security.authorization.restriction.RestrictionProvider;
import org.apache.jackrabbit.oak.spi.security.privilege.PrivilegeBits;
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
    //
    // - what kind of rights do I need to run chmod?
    // - does chown check if the new owner exists?
    //
    // - implement validator to protect internal properties
    //
    // - bootstrapping problem with initial content: user info is 'null'
    //
    // - all sling code works with "JackrabbitAccessControlList" so this might
    // need to be reflected in this model as well
    //
    // permissions:
    // NODE_TYPE_MANAGEMENT is needed whenever a user adds a new typed node
    //
    // SecurityProviderRegistration should only bind to configs that are listed
    // as required and ignore everything else

    // - any set policy should bubble down to all child nodes for sling to work
    // as before

    public static String MIX_REP_FAUX_UNIX = "rep:FauxUnixMixin";
    static final String REP_USER = "rep:user";
    static final String REP_GROUP = "rep:group";
    static final String REP_PERMISSIONS = "rep:permissions";

    static final String DEFAULT_PERMISSIONS = "-rw-r-----";

    private static boolean USE_ACL_MODEL = Boolean.getBoolean("useACLModel");

    @Override
    public AccessControlManager getAccessControlManager(Root root, NamePathMapper namePathMapper) {
        if (USE_ACL_MODEL) {
            return FauxUnixACLs.getAccessControlManager(root, namePathMapper, getSecurityProvider());
        } else {
            return FauxUnixSimplePolicies.getAccessControlManager(root, namePathMapper, getSecurityProvider());
        }
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
        // TODO PermissionValidatorProvider is part of a package in oak-core
        // that is not OSGi exported
        // PermissionValidatorProvider pvp = new
        // PermissionValidatorProvider(getSecurityProvider(), workspaceName,
        // principals, moveTracker, getRootProvider(), getTreeProvider());
        // return Collections.singletonList(pvp);
        return Collections.emptyList();
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
        public Set<String> getPrivileges(@Nullable Tree tree) {
            // TODO
            log.info("getPrivileges({})", getPath(tree));
            throw new RuntimeException("not supported");
        }

        @Override
        public RepositoryPermission getRepositoryPermission() {
            log.info("getRepositoryPermission=EMPTY");
            return RepositoryPermission.EMPTY;
        }

        @Override
        public TreePermission getTreePermission(@Nullable Tree tree, TreePermission parentPermission) {
            TreePermission p = new FauxUnixPermission(tree, asNames(principals));
            log.info("getTreePermission({}, {})={}", getPath(tree), parentPermission, p);
            return p;
        }

        @Override
        public TreePermission getTreePermission(@Nullable Tree tree, TreeType type, TreePermission parentPermission) {
            TreePermission p = new FauxUnixPermission(tree, asNames(principals));
            log.info("getTreePermission({}, {}, {})={}", getPath(tree), type, parentPermission, p);
            return p;
        }

        @Override
        public boolean hasPrivileges(@Nullable Tree tree, String... privilegeNames) {
            // TODO
            log.info("getPrivileges({}, {})", getPath(tree), Arrays.toString(privilegeNames));
            throw new RuntimeException("not supported");
        }

        @Override
        public boolean isGranted(@Nullable Tree tree, PropertyState property, long permissions) {
            TreePermission p = new FauxUnixPermission(tree, asNames(principals));
            boolean is = p.isGranted(permissions, property);
            log.info("isGranted({}, {}, {})={}", getPath(tree), getPropertyName(property),
                    Permissions.getNames(permissions), is);
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
        public PrivilegeBits supportedPrivileges(@Nullable Tree tree, PrivilegeBits privilegeBits) {
            // TODO
            log.info("supportedPrivileges({}, {})", getPath(tree), privilegeBits);
            throw new RuntimeException("not supported");
        }

        @Override
        public long supportedPermissions(@Nullable Tree tree, PropertyState property, long permissions) {
            long supported = supported(permissions);
            if (supported != Permissions.NO_PERMISSION) {
                log.info("supportedPermissions({}, {}, {})={}", getPath(tree), getPropertyName(property),
                        Permissions.getNames(permissions), Permissions.getNames(supported));
                return supported;
            } else {
                log.info("supportedPermissions({}, {}, {})=NO_PERMISSION", getPath(tree), getPropertyName(property),
                        getPropertyName(property));
                return Permissions.NO_PERMISSION;
            }
        }

        @Override
        public long supportedPermissions(TreeLocation location, long permissions) {
            long supported = supported(permissions);
            if (supported != Permissions.NO_PERMISSION) {
                log.info("supportedPermissions({}, {})={}", location, Permissions.getNames(permissions),
                        Permissions.getNames(supported));
                return supported;
            } else {
                log.info("supportedPermissions({}, {})=NO_PERMISSION", location, Permissions.getNames(permissions));
                return Permissions.NO_PERMISSION;
            }
        }

        @Override
        public long supportedPermissions(TreePermission treePermission, PropertyState property, long permissions) {
            long supported = permissions & Permissions.READ;
            if (supported != Permissions.NO_PERMISSION && (treePermission instanceof FauxUnixPermission)) {
                log.info("supportedPermissions({}, {}, {})={}", treePermission, getPropertyName(property),
                        Permissions.getNames(permissions), Permissions.getNames(supported));
                return supported;
            } else {
                log.info("supportedPermissions({}, {}, {})=NO_PERMISSION", treePermission, getPropertyName(property),
                        Permissions.getNames(permissions));
                return Permissions.NO_PERMISSION;
            }
        }

        private static long supported(long permissions) {
            long supported = permissions & (Permissions.READ | Permissions.WRITE | Permissions.NODE_TYPE_MANAGEMENT);
            return supported;
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

            if (Permissions.includes(Permissions.NODE_TYPE_MANAGEMENT, permissions)) {
                // same as write
                boolean r = isAllow(false);
                log.info("isGranted({}, NODE_TYPE_MANAGEMENT)={}", tree.getPath(), r);
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
                log.info("warn no permission info on {}" + tree.getPath());
                perms = DEFAULT_PERMISSIONS;
            }

            // user
            if (principals.contains(u) && (read && perms.charAt(1) == 'r' || perms.charAt(2) == 'w')) {
                return true;
            }

            // group
            Set<String> groups = getGroupsOrEmpty(t);
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
                groups = Suppliers.ofInstance(asNames(principals));
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
                    new EditorHook(
                            new CompositeEditorProvider(new NamespaceEditorProvider(), new TypeEditorProvider())),
                    new FauxUnixHook(adminId));
            Root root = rootProvider.createSystemRoot(store, hook);
            if (registerNodeTypes(root)) {
                NodeState target = store.getRoot();
                target.compareAgainstBaseState(base, new ApplyDiff(builder));
                log.info("installed required node types");
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
