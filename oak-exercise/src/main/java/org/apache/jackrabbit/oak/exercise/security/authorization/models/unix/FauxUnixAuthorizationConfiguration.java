package org.apache.jackrabbit.oak.exercise.security.authorization.models.unix;

import java.security.Principal;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
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
import org.apache.jackrabbit.oak.api.PropertyState;
import org.apache.jackrabbit.oak.api.Root;
import org.apache.jackrabbit.oak.api.Tree;
import org.apache.jackrabbit.oak.api.Type;
import org.apache.jackrabbit.oak.namepath.NamePathMapper;
import org.apache.jackrabbit.oak.plugins.tree.TreeLocation;
import org.apache.jackrabbit.oak.plugins.tree.TreeType;
import org.apache.jackrabbit.oak.plugins.tree.TreeUtil;
import org.apache.jackrabbit.oak.spi.security.SecurityProvider;
import org.apache.jackrabbit.oak.spi.security.authorization.accesscontrol.AbstractAccessControlManager;
import org.apache.jackrabbit.oak.spi.security.authorization.accesscontrol.PolicyOwner;
import org.apache.jackrabbit.oak.spi.security.authorization.permission.AggregatedPermissionProvider;
import org.apache.jackrabbit.oak.spi.security.authorization.permission.PermissionProvider;
import org.apache.jackrabbit.oak.spi.security.authorization.permission.Permissions;
import org.apache.jackrabbit.oak.spi.security.authorization.permission.RepositoryPermission;
import org.apache.jackrabbit.oak.spi.security.authorization.permission.TreePermission;
import org.apache.jackrabbit.oak.spi.security.principal.PrincipalConfiguration;
import org.apache.jackrabbit.oak.spi.security.principal.PrincipalImpl;
import org.apache.jackrabbit.oak.spi.security.privilege.PrivilegeBits;
import org.apache.jackrabbit.oak.spi.state.NodeState;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class FauxUnixAuthorizationConfiguration extends AbstractAuthorizationConfiguration {

    public static final String REP_USER = "rep:user";
    public static final String REP_PERMISSIONS = "rep:permissions";

    public static final String DEFAULT_PERMISSIONS = "-rw-------";

    @Override
    public AccessControlManager getAccessControlManager(Root root, NamePathMapper namePathMapper) {
        return new FauxUnixACM(root, namePathMapper, getSecurityProvider());
    }

    @Override
    public PermissionProvider getPermissionProvider(Root root, String workspaceName, Set<Principal> principals) {
        return new FauxUnixPP(principals);
    }

    private static class FauxUnixACM extends AbstractAccessControlManager implements PolicyOwner {

        private static final Logger log = LoggerFactory.getLogger(FauxUnixACM.class);

        private final PrincipalManager principalManager;

        protected FauxUnixACM(Root root, NamePathMapper namePathMapper, SecurityProvider securityProvider) {
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
                // TODO group, other
                String u = TreeUtil.getString(t, REP_USER);
                return new UnixPolicyImpl(oakPath, getNamePathMapper(), asPrincipal(u));
            }
            return null;
        }

        private Principal asPrincipal(String principalName) {
            Principal principal = principalManager.getPrincipal(principalName);
            if (principal == null) {
                principal = new PrincipalImpl(principalName);
            }
            return principal;
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
            // TODO only sudo can run chown
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

        private final NamePathMapper namePathMapper;

        private final Principal principal;

        public UnixPolicyImpl(String oakPath, NamePathMapper namePathMapper, @Nonnull Principal principal) {
            this.oakPath = oakPath;
            this.namePathMapper = namePathMapper;
            this.principal = principal;
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

    private static class FauxUnixPP implements AggregatedPermissionProvider {

        private static final Logger log = LoggerFactory.getLogger(FauxUnixPP.class);

        private final Set<Principal> principals;

        public FauxUnixPP(@Nonnull Set<Principal> principals) {
            this.principals = Collections.unmodifiableSet(principals);
        }

        @Override
        public void refresh() {
            log.info("refresh");
        }

        @Override
        public Set<String> getPrivileges(Tree tree) {
            // TODO
            log.info("getPrivileges ({})", tree);
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
            log.info("getTreePermission ({}, {})", tree, parentPermission);
            return p;
        }

        @Override
        public TreePermission getTreePermission(Tree tree, TreeType type, TreePermission parentPermission) {
            TreePermission p = new FauxUnixPermission(tree, asNames(principals));
            log.info("getTreePermission ({}, {}, {})", tree.getPath(), type, parentPermission);
            return p;
        }

        @Override
        public boolean hasPrivileges(Tree tree, String... privilegeNames) {
            // TODO
            log.info("getPrivileges ({}, {})", tree, Arrays.toString(privilegeNames));
            throw new RuntimeException("not supported");
        }

        @Override
        public boolean isGranted(Tree tree, PropertyState property, long permissions) {
            // TODO
            log.info("isGranted ({}, {}, {})", tree, property, permissions);
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
            log.info("supportedPrivileges ({}, {})", tree, privilegeBits);
            throw new RuntimeException("not supported");
        }

        @Override
        public long supportedPermissions(Tree tree, PropertyState property, long permissions) {
            // TODO
            log.info("supportedPermissions ({}, {}, {})", tree, property, permissions);
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
                log.info("supportedPermissions ({}, {}, {}) = {}", treePermission, property, permissions, supported);
                return supported;
            } else {
                log.info("supportedPermissions ({}, {}, {}) = NO_PERMISSION", treePermission, property, permissions);
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
            log.info("getChildPermission ({}, {})", tree.getPath(), childName);
            return new FauxUnixPermission(tree.getChild(childName), principals);
        }

        @Override
        public boolean canReadAll() {
            log.info("canReadAll({}) = false", tree.getPath());
            return false;
        }

        @Override
        public boolean canRead() {
            boolean r = isAllow();
            log.info("canRead({}) = {}", tree.getPath(), r);
            return r;
        }

        @Override
        public boolean canReadProperties() {
            boolean r = isAllow();
            log.info("canReadProperties({}) = {}", tree.getPath(), r);
            return r;
        }

        @Override
        public boolean canRead(PropertyState property) {
            boolean r = isAllow();
            log.info("canRead({}, {}) = {}", tree.getPath(), property.getName(), r);
            return r;
        }

        @Override
        public boolean isGranted(long permissions) {
            if (permissions == Permissions.READ) {
                boolean r = isAllow();
                log.info("isGranted({}, READ) = {}", tree.getPath(), r);
                return r;
            }

            log.info("isGranted({}, {}) = false", tree.getPath(), permissions);
            return false;
        }

        @Override
        public boolean isGranted(long permissions, PropertyState property) {
            return isGranted(permissions);
        }

        private boolean isAllow() {
            if (principals.contains("system") || principals.contains("admin")) {
                log.info("allow bypass for {}", tree.getPath());
                return true;
            }

            // -rw-rw----
            String u = TreeUtil.getString(tree, REP_USER);
            String perms = TreeUtil.getString(tree, REP_PERMISSIONS);
            if (principals.contains(u)) {
                return perms.charAt(1) == 'r';
            }
            return false;
        }

        @Override
        public String toString() {
            return "FauxUnixPermission [path=" + tree.getPath() + ", principals=" + principals + "]";
        }

    }

}
