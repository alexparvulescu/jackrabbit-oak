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
package org.apache.jackrabbit.oak.security.user;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;

import java.security.Principal;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.UUID;

import org.apache.jackrabbit.api.security.user.Authorizable;
import org.apache.jackrabbit.api.security.user.Group;
import org.apache.jackrabbit.oak.AbstractSecurityTest;
import org.apache.jackrabbit.oak.spi.security.principal.EveryonePrincipal;
import org.junit.Test;
import org.mockito.Mockito;

import com.google.common.collect.Iterators;
import com.google.common.collect.Lists;

public class GroupImplTest extends AbstractSecurityTest {

    private final String groupId = "gr" + UUID.randomUUID();

    private UserManagerImpl uMgr;
    private GroupImpl group;

    @Override
    public void before() throws Exception {
        super.before();

        uMgr = new UserManagerImpl(root, getNamePathMapper(), getSecurityProvider());
        Group g = uMgr.createGroup(groupId);

        group = new GroupImpl(groupId, root.getTree(g.getPath()), uMgr);
    }

    @Override
    public void after() throws Exception {
        try {
            root.refresh();
        } finally {
            super.after();
        }
    }

    @Test(expected = IllegalArgumentException.class)
    public void testCheckValidTree() throws Exception {
        new GroupImpl(getTestUser().getID(), root.getTree(getTestUser().getPath()), uMgr);
    }

    @Test
    public void testAddMemberInvalidAuthorizable() throws Exception {
        assertFalse(group.addMember(Mockito.mock(Authorizable.class)));
    }

    @Test
    public void testAddMemberEveryone() throws Exception {
        Group everyoneGroup = uMgr.createGroup(EveryonePrincipal.getInstance());
        assertFalse(group.addMember(everyoneGroup));
    }

    @Test
    public void testAddMemberItself() throws Exception {
        assertFalse(group.addMember(group));
    }

    @Test
    public void testRemoveMemberInvalidAuthorizable() throws Exception {
        assertFalse(group.removeMember(Mockito.mock(Authorizable.class)));
    }

    @Test
    public void testRemoveNotMember() throws Exception {
        assertFalse(group.removeMember(getTestUser()));
    }

    @Test
    public void testIsMemberInvalidAuthorizable() throws Exception {
        assertFalse(group.isMember(Mockito.mock(Authorizable.class)));
    }

    @Test
    public void testGroupPrincipal() throws Exception {
        Principal groupPrincipal = group.getPrincipal();
        assertTrue(groupPrincipal instanceof AbstractGroupPrincipal);

        AbstractGroupPrincipal agp = (AbstractGroupPrincipal) groupPrincipal;
        assertSame(uMgr, agp.getUserManager());
        assertEquals(group.isEveryone(), agp.isEveryone());
    }

    @Test
    public void testGroupPrincipalIsMember() throws Exception {
        group.addMember(getTestUser());

        AbstractGroupPrincipal groupPrincipal = (AbstractGroupPrincipal) group.getPrincipal();
        assertTrue(groupPrincipal.isMember(getTestUser()));
    }

    @Test
    public void testGroupPrincipalMembers() throws Exception {
        group.addMember(getTestUser());

        AbstractGroupPrincipal groupPrincipal = (AbstractGroupPrincipal) group.getPrincipal();
        Iterator<Authorizable> members = groupPrincipal.getMembers();
        assertTrue(Iterators.elementsEqual(group.getMembers(), members));
    }

    @Test
    public void testMembersSetGetRmInline() throws Exception {
        addMembers(50);
    }

    @Test
    public void testMembersSetGetRmTree1() throws Exception {
        addMembers(150);
    }

    @Test
    public void testMembersSetGetRmTree2() throws Exception {
        addMembers(1510);
    }

    private void addMembers(int size) throws Exception {
        String[] tests = new String[size];
        for (int i = 0; i < size; i++) {
            String id = "user" + System.currentTimeMillis() + "-" + i;
            tests[i] = id;
            assertTrue(uMgr.createGroup(id) != null);
        }
        Arrays.sort(tests);

        Set<String> res1 = group.addMembers(tests);
        assertTrue("unable to add [" + res1.size() + "] " + res1, res1.isEmpty());

        List<Authorizable> out = Lists.newArrayList(group.getMembers());
        assertEquals(size, out.size());

        String[] got = new String[size];
        int i = 0;
        for (Authorizable a : out) {
            got[i++] = a.getID();
        }
        Arrays.sort(got);
        assertArrayEquals("membership sets not equal", tests, got);

        Set<String> res2 = group.removeMembers(tests);
        assertTrue("unable to remove " + res2, res2.isEmpty());

        List<Authorizable> out2 = Lists.newArrayList(group.getMembers());
        assertEquals(0, out2.size());
    }
}