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

import static org.apache.jackrabbit.oak.exercise.security.authorization.models.unix.FauxUnixAuthorizationConfiguration.DEFAULT_PERMISSIONS;
import static org.apache.jackrabbit.oak.exercise.security.authorization.models.unix.FauxUnixAuthorizationConfiguration.MIX_REP_FAUX_UNIX;
import static org.apache.jackrabbit.oak.exercise.security.authorization.models.unix.FauxUnixAuthorizationConfiguration.REP_GROUP;
import static org.apache.jackrabbit.oak.exercise.security.authorization.models.unix.FauxUnixAuthorizationConfiguration.REP_PERMISSIONS;
import static org.apache.jackrabbit.oak.exercise.security.authorization.models.unix.FauxUnixAuthorizationConfiguration.REP_USER;
import static org.apache.jackrabbit.oak.exercise.security.authorization.models.unix.FauxUnixAuthorizationHelper.getGroupsOrEmpty;
import static org.apache.jackrabbit.oak.exercise.security.authorization.models.unix.FauxUnixAuthorizationHelper.isAdmin;

import java.security.Principal;
import java.util.Collections;
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
import javax.jcr.security.AccessControlPolicy;
import javax.jcr.security.AccessControlPolicyIterator;
import javax.jcr.security.Privilege;
import javax.jcr.version.VersionException;

import org.apache.jackrabbit.api.security.JackrabbitAccessControlManager;
import org.apache.jackrabbit.api.security.JackrabbitAccessControlPolicy;
import org.apache.jackrabbit.commons.iterator.AccessControlPolicyIteratorAdapter;
import org.apache.jackrabbit.oak.api.AuthInfo;
import org.apache.jackrabbit.oak.api.Root;
import org.apache.jackrabbit.oak.api.Tree;
import org.apache.jackrabbit.oak.api.Type;
import org.apache.jackrabbit.oak.namepath.NamePathMapper;
import org.apache.jackrabbit.oak.plugins.tree.TreeUtil;
import org.apache.jackrabbit.oak.spi.nodetype.NodeTypeConstants;
import org.apache.jackrabbit.oak.spi.security.SecurityProvider;
import org.apache.jackrabbit.oak.spi.security.authorization.accesscontrol.AbstractAccessControlManager;
import org.apache.jackrabbit.oak.spi.security.authorization.accesscontrol.PolicyOwner;
import org.apache.jackrabbit.oak.spi.security.authorization.permission.Permissions;
import org.apache.jackrabbit.oak.spi.security.privilege.PrivilegeConstants;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class FauxUnixSimplePolicies {

    private FauxUnixSimplePolicies() {
    }

    public static JackrabbitAccessControlManager getAccessControlManager(Root root, NamePathMapper namePathMapper,
            SecurityProvider securityProvider) {
        return new FauxUnixAccessControlManager(root, namePathMapper, securityProvider);
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
                return new FauxUnixPolicyImpl(t, getNamePathMapper());
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
            this.groups = getGroupsOrEmpty(tree);
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

}
