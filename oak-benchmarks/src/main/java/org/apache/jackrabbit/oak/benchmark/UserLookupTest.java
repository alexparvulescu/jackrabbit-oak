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
package org.apache.jackrabbit.oak.benchmark;

import static org.apache.jackrabbit.commons.jackrabbit.authorization.AccessControlUtils.addAccessControlEntry;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Random;
import java.util.Set;
import java.util.TreeSet;

import javax.jcr.RepositoryException;
import javax.jcr.Session;
import javax.jcr.SimpleCredentials;
import javax.jcr.security.Privilege;

import org.apache.jackrabbit.api.JackrabbitSession;
import org.apache.jackrabbit.api.security.user.Authorizable;
import org.apache.jackrabbit.api.security.user.Group;
import org.apache.jackrabbit.api.security.user.Query;
import org.apache.jackrabbit.api.security.user.QueryBuilder;
import org.apache.jackrabbit.api.security.user.User;
import org.apache.jackrabbit.api.security.user.UserManager;

import com.google.common.collect.Iterators;

public class UserLookupTest extends AbstractTest {

    private final int tenantCount = 3;
    private final int groups = 200 * tenantCount;
    private final int users = 5 * groups;
    private final boolean debug = false;
    private final boolean runAsAdmin;
    private final Random random = new Random();

    private Map<String, List<String>> tenantGroups;
    private Map<String, List<String>> tenantUsers;

    public UserLookupTest(boolean runAsAdmin) {
        this.runAsAdmin = runAsAdmin;
    }

    @Override
    public void beforeSuite() throws Exception {
        super.beforeSuite();

        long start = System.currentTimeMillis();
        Session s = loginAdministrative();
        UserManager userManager = ((JackrabbitSession) s).getUserManager();
        try {
            Map<Group, List<Group>> tenants = addTenants(tenantCount, userManager);
            tenantGroups = addGroups(groups, tenants, userManager);
            tenantUsers = addUsers(users, tenants, userManager, random);
            for (Group g : tenants.keySet()) {
                addAccessControlEntry(s, "/", g.getPrincipal(), new String[] { Privilege.JCR_READ }, true);
                for (Group c : tenants.get(g)) {
                    addAccessControlEntry(s, g.getPath(), c.getPrincipal(), new String[] { Privilege.JCR_READ }, true);
                }
            }

        } finally {
            s.save();
            s.logout();
        }
        long dur = System.currentTimeMillis() - start;
        System.out.println("setup done in " + dur + " ms. run as Admin: " + runAsAdmin);
    }

    private static Map<Group, List<Group>> addTenants(int tenantCount, UserManager userManager)
            throws RepositoryException {
        Map<Group, List<Group>> tenants = new HashMap<>();
        for (int i = 0; i < tenantCount; i++) {
            Group t = userManager.createGroup("tenant" + i);
            tenants.put(t, new ArrayList<>());
        }
        return tenants;
    }

    private static Map<String, List<String>> addGroups(int groups, Map<Group, List<Group>> tenants,
            UserManager userManager) throws RepositoryException {
        Map<String, List<String>> tToG = new HashMap<>();
        for (Group g : tenants.keySet()) {
            tToG.put(g.getID(), new ArrayList<>());
        }

        Iterator<Entry<Group, List<Group>>> tsI = Iterators.cycle(tenants.entrySet());
        for (int i = 0; i < groups; i++) {
            Group g = userManager.createGroup("group" + i);
            Entry<Group, List<Group>> e = tsI.next();
            e.getKey().addMember(g);
            e.getValue().add(g);
            tToG.get(e.getKey().getID()).add(g.getID());
        }
        return tToG;
    }

    private static Map<String, List<String>> addUsers(int users, Map<Group, List<Group>> tenants,
            UserManager userManager, Random random) throws RepositoryException {
        List<String> ids = new ArrayList<>();
        Iterator<String> name = Iterators.cycle("a", "b", "c", "d");
        for (int i = 0; i < users; i++) {
            String up = name.next() + "User" + i;
            User u = userManager.createUser(up, up);
            ids.add(u.getID());
        }
        Collections.shuffle(ids, random);

        Map<String, List<String>> tToU = new HashMap<>();
        for (Group g : tenants.keySet()) {
            tToU.put(g.getID(), new ArrayList<>());
        }

        Iterator<Entry<Group, List<Group>>> tsI = Iterators.cycle(tenants.entrySet());
        for (String id : ids) {
            // each user is part of 2 tenants
            Entry<Group, List<Group>> e0 = tsI.next();
            addUserToTenant(id, e0.getValue(), random);
            tToU.get(e0.getKey().getID()).add(id);

            Entry<Group, List<Group>> e1 = tsI.next();
            addUserToTenant(id, e1.getValue(), random);
            tToU.get(e1.getKey().getID()).add(id);
        }
        return tToU;
    }

    private static void addUserToTenant(String id, List<Group> groups, Random random) throws RepositoryException {
        int times = groups.size() / 10;
        assertTrue(times > 0);
        for (int i = 0; i < times; i++) {
            groups.get(random.nextInt(groups.size())).addMembers(id);
        }
    }

    @Override
    protected void runTest() throws Exception {
        if (debug) {
            System.err.println("Tenant -> Groups");
            for (Entry<String, List<String>> e : tenantGroups.entrySet()) {
                Collections.sort(e.getValue());
                System.err.println(e.getKey() + " (" + e.getValue().size() + "): " + e.getValue());
            }
            System.err.println("Tenant -> Users");
            for (Entry<String, List<String>> e : tenantUsers.entrySet()) {
                Collections.sort(e.getValue());
                System.err.println(e.getKey() + " (" + e.getValue().size() + "): " + e.getValue());
            }
        }

        Entry<String, List<String>> e = tenantUsers.entrySet().iterator().next();
        String tId = e.getKey();
        String uId = e.getValue().get(0);
        Set<String> expected = new TreeSet<>();
        for (String u : tenantUsers.get(tId)) {
            if (u.startsWith("a")) {
                expected.add(u);
            }
        }
        if (debug) {
            System.out.println("tenant id " + tId + ", expecting " + expected.size() + " users.");
        }

        Session s;
        if (runAsAdmin) {
            s = loginAdministrative();
        } else {
            s = login(new SimpleCredentials(uId, uId.toCharArray()));
        }

        Query q = new Query() {
            @Override
            public <T> void build(QueryBuilder<T> builder) {
                builder.setCondition(builder.nameMatches("a%"));
                builder.setScope(tId, false);
            }
        };

        UserManager userManager = ((JackrabbitSession) s).getUserManager();
        Iterator<Authorizable> res = userManager.findAuthorizables(q);
        assertTrue(res.hasNext());
        while (res.hasNext()) {
            String id = res.next().getID();
            assertTrue("unexpected result " + id, expected.remove(id));
        }
        assertTrue("items left " + expected.size(), expected.isEmpty());
    }

}
