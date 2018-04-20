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

import static org.apache.jackrabbit.oak.spi.security.privilege.PrivilegeConstants.JCR_NODE_TYPE_MANAGEMENT;
import static org.apache.jackrabbit.oak.spi.security.privilege.PrivilegeConstants.JCR_READ;
import static org.apache.jackrabbit.oak.spi.security.privilege.PrivilegeConstants.JCR_WRITE;

import java.security.Principal;
import java.util.HashSet;
import java.util.Set;

import javax.annotation.CheckForNull;
import javax.annotation.Nonnull;
import javax.jcr.RepositoryException;
import javax.jcr.security.AccessControlEntry;
import javax.jcr.security.AccessControlManager;
import javax.jcr.security.AccessControlPolicy;
import javax.jcr.security.Privilege;

import org.apache.jackrabbit.api.security.authorization.PrivilegeManager;
import org.apache.jackrabbit.oak.api.PropertyState;
import org.apache.jackrabbit.oak.api.Tree;
import org.apache.jackrabbit.oak.exercise.security.authorization.models.unix.FauxUnixACLs.FauxUnixACL;
import org.apache.jackrabbit.oak.exercise.security.authorization.models.unix.FauxUnixACLs.OwnerACE;
import org.apache.jackrabbit.oak.exercise.security.authorization.models.unix.FauxUnixSimplePolicies.FauxUnixPolicy;
import org.apache.jackrabbit.oak.exercise.security.authorization.models.unix.FauxUnixSimplePolicies.FauxUnixPolicyImpl;
import org.apache.jackrabbit.oak.plugins.tree.TreeUtil;
import org.apache.jackrabbit.oak.spi.security.principal.AdminPrincipal;
import org.apache.jackrabbit.oak.spi.security.principal.SystemPrincipal;

import com.google.common.collect.Sets;

public class FauxUnixAuthorizationHelper {

    private FauxUnixAuthorizationHelper() {
    }

    public static boolean isAdmin(@Nonnull Set<Principal> principals) {
        return principals.contains(SystemPrincipal.INSTANCE)
                || principals.stream().anyMatch((p) -> p instanceof AdminPrincipal);
    }

    public static boolean chown(@Nonnull String path, @Nonnull String owner, @Nonnull AccessControlManager acm)
            throws RepositoryException {
        AccessControlPolicy[] eff = acm.getPolicies(path);
        if (eff.length == 0) {
            return false;
        }

        if (eff[0] instanceof FauxUnixPolicy) {
            FauxUnixPolicyImpl fup = (FauxUnixPolicyImpl) eff[0];
            fup.setOwner(owner);
            acm.setPolicy(path, fup);
            return true;
        } else {
            FauxUnixACL acl = (FauxUnixACL) eff[0];
            boolean changed = false;
            for (AccessControlEntry ace : acl.getAccessControlEntries()) {
                if (ace instanceof OwnerACE) {
                    OwnerACE ownerAce = (OwnerACE) ace;
                    ownerAce.setPrincipal(owner);
                    changed = true;
                    break;
                }
            }
            if (changed) {
                acm.setPolicy(path, acl);
                return true;
            }
            return false;
        }
    }

    public static boolean chgrp(@Nonnull String path, @Nonnull Set<String> group, @Nonnull AccessControlManager acm)
            throws RepositoryException {
        AccessControlPolicy[] eff = acm.getPolicies(path);
        if (eff.length == 0) {
            return false;
        }
        FauxUnixPolicyImpl fup = (FauxUnixPolicyImpl) eff[0];
        fup.setGroups(group);
        acm.setPolicy(path, fup);
        return true;
    }

    public static boolean chmod(@Nonnull String path, @Nonnull String flags, @Nonnull AccessControlManager acm)
            throws RepositoryException {
        AccessControlPolicy[] eff = acm.getPolicies(path);
        if (eff.length == 0) {
            return false;
        }
        FauxUnixPolicyImpl fup = (FauxUnixPolicyImpl) eff[0];
        fup.setPermissions(flags);
        acm.setPolicy(path, fup);
        return true;
    }

    @CheckForNull
    public static FauxUnixPolicy getPolicy(@Nonnull String path, @Nonnull AccessControlManager acm) {
        AccessControlPolicy[] eff = null;
        try {
            eff = acm.getPolicies(path);
        } catch (RepositoryException e) {
            // ignore
        }

        if (eff == null || eff.length == 0) {
            return null;
        }
        if (eff.length > 1) {
            throw new IllegalStateException();
        }
        return (FauxUnixPolicy) eff[0];
    }

    public static Set<String> asNames(Set<? extends Principal> principals) {
        Set<String> ps = new HashSet<>();
        for (Principal p : principals) {
            ps.add(p.getName());
        }
        return ps;
    }

    public static Set<String> getGroupsOrEmpty(Tree tree) {
        Iterable<String> g = TreeUtil.getStrings(tree, FauxUnixAuthorizationConfiguration.REP_GROUP);
        if (g == null) {
            return Sets.newHashSet();
        } else {
            return Sets.newHashSet(g);
        }
    }

    public static String getPath(Tree tree) {
        if (tree != null) {
            return tree.getPath();
        } else {
            return "";
        }
    }

    public static String getPropertyName(PropertyState ps) {
        if (ps != null) {
            return ps.getName();
        } else {
            return "";
        }
    }

    public static Privilege[] privileges(String permissions, int index, PrivilegeManager privilegeManager)
            throws RepositoryException {
        boolean isRead = permissions.charAt(index) == 'r';
        boolean isWrite = permissions.charAt(index + 1) == 'w';
        if (isRead && isWrite) {
            return new Privilege[] { privilegeManager.getPrivilege(JCR_READ), privilegeManager.getPrivilege(JCR_WRITE),
                    privilegeManager.getPrivilege(JCR_NODE_TYPE_MANAGEMENT) };
        } else if (isRead) {
            return new Privilege[] { privilegeManager.getPrivilege(JCR_READ) };
        } else if (isWrite) {
            return new Privilege[] { privilegeManager.getPrivilege(JCR_WRITE),
                    privilegeManager.getPrivilege(JCR_NODE_TYPE_MANAGEMENT) };
        } else {
            return new Privilege[] {};
        }
    }
}
