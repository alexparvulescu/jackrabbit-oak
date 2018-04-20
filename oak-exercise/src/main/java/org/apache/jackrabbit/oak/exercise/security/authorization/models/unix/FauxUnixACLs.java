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

import static org.apache.jackrabbit.oak.exercise.security.authorization.models.unix.FauxUnixAuthorizationConfiguration.MIX_REP_FAUX_UNIX;
import static org.apache.jackrabbit.oak.exercise.security.authorization.models.unix.FauxUnixAuthorizationConfiguration.REP_GROUP;
import static org.apache.jackrabbit.oak.exercise.security.authorization.models.unix.FauxUnixAuthorizationConfiguration.REP_PERMISSIONS;
import static org.apache.jackrabbit.oak.exercise.security.authorization.models.unix.FauxUnixAuthorizationConfiguration.REP_USER;
import static org.apache.jackrabbit.oak.exercise.security.authorization.models.unix.FauxUnixAuthorizationHelper.getGroupsOrEmpty;
import static org.apache.jackrabbit.oak.exercise.security.authorization.models.unix.FauxUnixAuthorizationHelper.isAdmin;

import java.security.Principal;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.annotation.CheckForNull;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.jcr.AccessDeniedException;
import javax.jcr.PathNotFoundException;
import javax.jcr.PropertyType;
import javax.jcr.RepositoryException;
import javax.jcr.UnsupportedRepositoryOperationException;
import javax.jcr.Value;
import javax.jcr.ValueFormatException;
import javax.jcr.lock.LockException;
import javax.jcr.security.AccessControlEntry;
import javax.jcr.security.AccessControlException;
import javax.jcr.security.AccessControlPolicy;
import javax.jcr.security.AccessControlPolicyIterator;
import javax.jcr.security.Privilege;
import javax.jcr.version.VersionException;

import org.apache.jackrabbit.api.security.JackrabbitAccessControlEntry;
import org.apache.jackrabbit.api.security.JackrabbitAccessControlManager;
import org.apache.jackrabbit.api.security.JackrabbitAccessControlPolicy;
import org.apache.jackrabbit.api.security.authorization.PrivilegeManager;
import org.apache.jackrabbit.commons.iterator.AccessControlPolicyIteratorAdapter;
import org.apache.jackrabbit.oak.api.AuthInfo;
import org.apache.jackrabbit.oak.api.Root;
import org.apache.jackrabbit.oak.api.Tree;
import org.apache.jackrabbit.oak.api.Type;
import org.apache.jackrabbit.oak.namepath.NamePathMapper;
import org.apache.jackrabbit.oak.plugins.tree.TreeUtil;
import org.apache.jackrabbit.oak.spi.nodetype.NodeTypeConstants;
import org.apache.jackrabbit.oak.spi.security.SecurityProvider;
import org.apache.jackrabbit.oak.spi.security.authorization.accesscontrol.AbstractAccessControlList;
import org.apache.jackrabbit.oak.spi.security.authorization.accesscontrol.AbstractAccessControlManager;
import org.apache.jackrabbit.oak.spi.security.authorization.accesscontrol.PolicyOwner;
import org.apache.jackrabbit.oak.spi.security.authorization.permission.Permissions;
import org.apache.jackrabbit.oak.spi.security.authorization.restriction.RestrictionProvider;
import org.apache.jackrabbit.oak.spi.security.principal.EveryonePrincipal;
import org.apache.jackrabbit.oak.spi.security.principal.PrincipalImpl;
import org.apache.jackrabbit.oak.spi.security.privilege.PrivilegeConstants;
import org.apache.jackrabbit.oak.spi.security.user.UserConfiguration;
import org.apache.jackrabbit.oak.spi.security.user.util.UserUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * an effort to get sling to work with the FauxUnix model by expressing policies
 * as ACLs. severely under implemented
 *
 */
public class FauxUnixACLs {

    private FauxUnixACLs() {
    }

    public static JackrabbitAccessControlManager getAccessControlManager(Root root, NamePathMapper namePathMapper,
            SecurityProvider securityProvider) {
        return new FauxUnixACM(root, namePathMapper, securityProvider);
    }

    private static class FauxUnixACM extends AbstractAccessControlManager implements PolicyOwner {

        private static final Logger log = LoggerFactory.getLogger(FauxUnixACM.class);

        private final String adminId;

        protected FauxUnixACM(Root root, NamePathMapper namePathMapper, SecurityProvider securityProvider) {
            super(root, namePathMapper, securityProvider);
            adminId = UserUtil.getAdminId(securityProvider.getConfiguration(UserConfiguration.class).getParameters());

        }

        @Nonnull
        @Override
        public Privilege[] getSupportedPrivileges(@Nullable String absPath) throws RepositoryException {
            Privilege[] r = new Privilege[] { privilegeFromName(PrivilegeConstants.JCR_READ),
                    privilegeFromName(PrivilegeConstants.JCR_WRITE),
                    privilegeFromName(PrivilegeConstants.JCR_NODE_TYPE_MANAGEMENT) };
            log.info("getSupportedPrivileges({})={}", absPath, r);
            return r;
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
            AccessControlPolicy pol = getPolicy(absPath);
            if (pol != null) {
                log.info("getPolicies({})=[{}]", absPath, pol);
                return new AccessControlPolicy[] { pol };
            }
            log.info("getPolicies({})=<empty>", absPath);
            return new AccessControlPolicy[0];
        }

        @CheckForNull
        private AccessControlPolicy getPolicy(@Nonnull String absPath) throws RepositoryException {
            String oakPath = getOakPath(absPath);
            if (oakPath != null) {
                Tree t = getTree(oakPath, Permissions.READ, false);
                if (t == null) {
                    return null;
                }
                return FauxUnixACL.newFauxUnixACL(t, getNamePathMapper(), getPrivilegeManager(), adminId);
            }
            return null;
        }

        @Override
        public AccessControlPolicy[] getEffectivePolicies(String absPath)
                throws PathNotFoundException, AccessDeniedException, RepositoryException {
            AccessControlPolicy pol = getPolicy(absPath);
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
            AccessControlPolicy pol = getPolicy(absPath);
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
            if (!(policy instanceof FauxUnixACL)) {
                throw new AccessControlException("Unsupported policy implementation: " + policy);
            }
            FauxUnixACL acl = (FauxUnixACL) policy;
            if (!acl.getPath().equals(absPath)) {
                throw new AccessControlException("Path mismatch: Expected " + absPath + ", Found: " + acl.getPath());
            }
            String oakPath = getOakPath(absPath);
            // TODO what kind of rights do I need to run chmod?
            Tree t = getTree(oakPath, Permissions.WRITE, false);
            FauxUnixACL.apply(acl, t, getRoot(), absPath);
            log.info("setPolicy ({})={}", oakPath, acl);
        }

        @Override
        public void removePolicy(String absPath, AccessControlPolicy policy) throws PathNotFoundException,
                AccessControlException, AccessDeniedException, LockException, VersionException, RepositoryException {
            throw new AccessControlException("remove not supported");
        }

        @Override
        public boolean defines(String absPath, AccessControlPolicy acp) {
            return acp instanceof FauxUnixACL;
        }
    }

    public static class FauxUnixACL extends AbstractAccessControlList {

        private static final Logger log = LoggerFactory.getLogger(FauxUnixACL.class);

        private List<FauxUnixACE> aces = new ArrayList<>();

        private List<GroupACE> tempA = new ArrayList<>();

        private List<GroupACE> tempD = new ArrayList<>();

        static FauxUnixACL newFauxUnixACL(@Nonnull Tree tree, @Nonnull NamePathMapper namePathMapper,
                PrivilegeManager privilegeManager, String adminId) throws RepositoryException {
            String owner = TreeUtil.getString(tree, REP_USER);
            if (owner == null) {
                owner = adminId;
            }
            Set<String> groups = getGroupsOrEmpty(tree);

            String permissions = TreeUtil.getString(tree, REP_PERMISSIONS);
            if (permissions == null) {
                // injecting default in case there is no info
                permissions = FauxUnixAuthorizationConfiguration.DEFAULT_PERMISSIONS;
            }

            List<FauxUnixACE> aces = new ArrayList<>();
            Privilege[] pO = FauxUnixAuthorizationHelper.privileges(permissions, 1, privilegeManager);
            if (pO.length > 0) {
                aces.add(new OwnerACE(new PrincipalImpl(owner), pO));
            }
            Privilege[] pG = FauxUnixAuthorizationHelper.privileges(permissions, 4, privilegeManager);
            if (pG.length > 0) {
                for (String g : groups) {
                    aces.add(new GroupACE(new PrincipalImpl(g), pG));
                }
            }
            Privilege[] pE = FauxUnixAuthorizationHelper.privileges(permissions, 7, privilegeManager);
            if (pE.length > 0) {
                aces.add(new OtherACE(EveryonePrincipal.getInstance(), pE));
            }
            return new FauxUnixACL(tree.getPath(), namePathMapper, aces);
        }

        static void apply(FauxUnixACL acl, Tree t, Root r, String absPath)
                throws RepositoryException, AccessControlException {
            String o = TreeUtil.getString(t, REP_USER);
            AuthInfo authInfo = r.getContentSession().getAuthInfo();
            if (!authInfo.getUserID().equals(o) && !isAdmin(authInfo.getPrincipals())) {
                throw new AccessControlException("Unsupported path: " + absPath);
            }

            Tree typeRoot = r.getTree(NodeTypeConstants.NODE_TYPES_PATH);
            // TODO handle permission changes
            String owner = null;
            Set<String> groupsAdd = new HashSet<>();
            Set<String> groupsRm = new HashSet<>();

            for (AccessControlEntry ace : acl.getAccessControlEntries()) {
                if (ace instanceof OwnerACE) {
                    owner = ((OwnerACE) ace).getPrincipal().getName();
                    break;
                }
            }
            if (owner != null) {
                if (!TreeUtil.isNodeType(t, MIX_REP_FAUX_UNIX, typeRoot)) {
                    TreeUtil.addMixin(t, MIX_REP_FAUX_UNIX, typeRoot, null);
                }
                t.setProperty(REP_USER, owner);
            }

            for (GroupACE ace : acl.tempA) {
                groupsAdd.add(ace.getPrincipal().getName());
            }
            for (GroupACE ace : acl.tempD) {
                groupsRm.add(ace.getPrincipal().getName());
            }
            if (!groupsAdd.isEmpty() || !groupsRm.isEmpty()) {
                groupUpdate(t, groupsAdd, groupsRm, typeRoot);
            }
        }

        private static void groupUpdate(Tree t, Set<String> groupsAdd, Set<String> groupsRm, Tree typeRoot)
                throws RepositoryException {
            log.info("groupUpdate {}, +{}, -{}", t.getPath(), groupsAdd, groupsRm);
            Set<String> groups = getGroupsOrEmpty(t);
            groups.addAll(groupsAdd);
            groups.removeAll(groupsRm);
            t.setProperty(REP_GROUP, groups, Type.STRINGS);

            if (!TreeUtil.isNodeType(t, MIX_REP_FAUX_UNIX, typeRoot)) {
                TreeUtil.addMixin(t, MIX_REP_FAUX_UNIX, typeRoot, null);
            }

            for (Tree c : t.getChildren()) {
                groupUpdate(c, groupsAdd, groupsRm, typeRoot);
            }

        }

        public FauxUnixACL(@Nonnull String path, @Nonnull NamePathMapper namePathMapper, List<FauxUnixACE> aces) {
            super(path, namePathMapper);
            this.aces = aces;
        }

        @Override
        public boolean addEntry(Principal principal, Privilege[] privileges, boolean isAllow,
                Map<String, Value> restrictions, Map<String, Value[]> mvRestrictions)
                throws AccessControlException, RepositoryException {

            if (EveryonePrincipal.getInstance().equals(principal)) {
                log.info("addEntry everyone, {}, ? {}", Arrays.toString(privileges), isAllow);

            } else {
                log.info("addEntry {}, {}, ? {}", principal.getName(), Arrays.toString(privileges), isAllow);
                if (isAllow) {
                    tempA.add(new GroupACE(principal, privileges));
                } else {
                    tempD.add(new GroupACE(principal, privileges));
                }
            }

            return false;
        }

        @Override
        public void orderBefore(AccessControlEntry srcEntry, AccessControlEntry destEntry)
                throws AccessControlException, UnsupportedRepositoryOperationException, RepositoryException {
            // noop
        }

        @Override
        public void removeAccessControlEntry(AccessControlEntry ace)
                throws AccessControlException, RepositoryException {
            throw new AccessControlException("cannot remove single entry");
        }

        @Override
        public List<? extends JackrabbitAccessControlEntry> getEntries() {
            List<FauxUnixACE> all = new ArrayList<>();
            all.addAll(aces);
            all.addAll(tempA);
            all.addAll(tempD);
            return all;
        }

        @Override
        public RestrictionProvider getRestrictionProvider() {
            return RestrictionProvider.EMPTY;
        }

        @Override
        public String toString() {
            return "FauxUnixACL [path=" + getPath() + ", aces=" + aces + "]";
        }

        @Override
        public int getRestrictionType(String restrictionName) throws RepositoryException {
            // needed for sling's AclVisitor
            return PropertyType.STRING;
        }
    }

    private static class OtherACE extends FauxUnixACE {
        public OtherACE(Principal principal, Privilege[] privileges) {
            super(principal, privileges);
        }

        @Override
        public String toString() {
            return "OtherACE [" + super.getPrincipal() + ", privileges=" + Arrays.toString(super.getPrivileges()) + "]";
        }
    }

    private static class GroupACE extends FauxUnixACE {
        public GroupACE(Principal principal, Privilege[] privileges) {
            super(principal, privileges);
        }

        @Override
        public String toString() {
            return "GroupACE [" + super.getPrincipal() + ", privileges=" + Arrays.toString(super.getPrivileges()) + "]";
        }
    }

    public static class OwnerACE extends FauxUnixACE {
        public OwnerACE(Principal principal, Privilege[] privileges) {
            super(principal, privileges);
        }

        @Override
        public String toString() {
            return "OwnerACE [" + super.getPrincipal() + ", privileges=" + Arrays.toString(super.getPrivileges()) + "]";
        }
    }

    private static class FauxUnixACE implements JackrabbitAccessControlEntry {

        private Principal principal;

        private final Privilege[] privileges;

        public FauxUnixACE(Principal principal, Privilege[] privileges) {
            this.principal = principal;
            this.privileges = privileges;
        }

        @Override
        public Principal getPrincipal() {
            return principal;
        }

        public void setPrincipal(String principal) {
            this.principal = new PrincipalImpl(principal);
        }

        @Override
        public Privilege[] getPrivileges() {
            return privileges;
        }

        @Override
        public boolean isAllow() {
            return true;
        }

        @Override
        public String[] getRestrictionNames() throws RepositoryException {
            return new String[] {};
        }

        @Override
        public Value getRestriction(String restrictionName) throws ValueFormatException, RepositoryException {
            throw new AccessControlException("not implemented");
        }

        @Override
        public Value[] getRestrictions(String restrictionName) throws RepositoryException {
            return new Value[] {};
        }
    }
}
