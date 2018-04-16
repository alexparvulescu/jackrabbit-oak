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

import java.security.Principal;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import javax.annotation.CheckForNull;
import javax.annotation.Nonnull;
import javax.jcr.RepositoryException;
import javax.jcr.security.AccessControlManager;
import javax.jcr.security.AccessControlPolicy;

import org.apache.jackrabbit.oak.api.Tree;
import org.apache.jackrabbit.oak.exercise.security.authorization.models.unix.FauxUnixAuthorizationConfiguration.FauxUnixPolicy;
import org.apache.jackrabbit.oak.exercise.security.authorization.models.unix.FauxUnixAuthorizationConfiguration.FauxUnixPolicyImpl;
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
        FauxUnixPolicyImpl fup = (FauxUnixPolicyImpl) eff[0];
        fup.setOwner(owner);
        acm.setPolicy(path, fup);
        return true;
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
            return Collections.emptySet();
        } else {
            return Sets.newHashSet(g);
        }
    }
}
