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

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.apache.jackrabbit.api.security.user.Group;
import org.apache.jackrabbit.api.security.user.User;
import org.apache.jackrabbit.api.security.user.UserManager;
import org.apache.jackrabbit.oak.AbstractSecurityTest;
import org.apache.jackrabbit.oak.api.Root;
import org.junit.Test;

public class RepMembersConflictHandlerTest extends AbstractSecurityTest {

    /**
     * The id of the test group
     */
    private static final String GROUP_ID = "test-groupId";

    private Group group;
    private User[] users;

    @Override
    public void before() throws Exception {
        super.before();
        UserManager um = getUserManager(root);
        // create a group to receive users
        group = um.createGroup(GROUP_ID);

        // create future members of the above group
        User u1 = um.createUser("u1", "pass");
        User u2 = um.createUser("u2", "pass");
        User u3 = um.createUser("u3", "pass");
        User u4 = um.createUser("u4", "pass");
        User u5 = um.createUser("u5", "pass");
        root.commit();

        users = new User[] { u1, u2, u3, u4, u5 };

    }

    /**
     * ADD-ADD test on an empty base
     */
    @Test
    public void testAddAddOnEmpty() throws Exception {

        Root r0 = login(getAdminCredentials()).getLatestRoot();
        Root r1 = login(getAdminCredentials()).getLatestRoot();

        add(r0, users[1].getID());
        add(r1, users[2].getID());

        // refresh to get the latest changes
        root.refresh();

        // verify users are now members (merged result)
        assertTrue(group.isDeclaredMember(users[1]));
        assertTrue(group.isDeclaredMember(users[2]));
    }

    /**
     * ADD-ADD test with a preexisting value
     */
    @Test
    public void testAddAdd() throws Exception {

        // pre-populate with an id
        add(root, users[0].getID());

        Root r0 = login(getAdminCredentials()).getLatestRoot();
        Root r1 = login(getAdminCredentials()).getLatestRoot();

        add(r0, users[1].getID());
        add(r1, users[2].getID());

        // refresh to get the latest changes
        root.refresh();

        // verify users are now members (merged result)
        assertTrue(group.isDeclaredMember(users[0]));
        assertTrue(group.isDeclaredMember(users[1]));
        assertTrue(group.isDeclaredMember(users[2]));
    }

    /**
     * Remove-Remove test
     */
    @Test
    public void testRmRm() throws Exception {

        // pre-populate with values
        add(root, users[0].getID(), users[1].getID(), users[2].getID());

        Root r0 = login(getAdminCredentials()).getLatestRoot();
        Root r1 = login(getAdminCredentials()).getLatestRoot();

        rm(r0, users[1].getID());
        rm(r1, users[2].getID());

        // refresh to get the latest changes
        root.refresh();

        // verify users are now members (merged result)
        assertTrue(group.isDeclaredMember(users[0]));
        assertFalse(group.isDeclaredMember(users[1]));
        assertFalse(group.isDeclaredMember(users[2]));
    }

    /**
     * Remove-Remove test
     */
    @Test
    public void testRmAdd() throws Exception {

        // pre-populate with values
        add(root, users[0].getID(), users[1].getID());

        Root r0 = login(getAdminCredentials()).getLatestRoot();
        Root r1 = login(getAdminCredentials()).getLatestRoot();

        rm(r0, users[1].getID());
        add(r1, users[2].getID());

        // refresh to get the latest changes
        root.refresh();

        // verify users are now members (merged result)
        assertTrue(group.isDeclaredMember(users[0]));
        assertFalse(group.isDeclaredMember(users[1]));
        assertTrue(group.isDeclaredMember(users[2]));
    }

    private void add(Root r, String... ids) throws Exception {
        UserManager um = getUserManager(r);
        Group g = (Group) um.getAuthorizable(GROUP_ID);
        for (String id : ids) {
            g.addMember(um.getAuthorizable(id));
        }
        r.commit();
    }

    private void rm(Root r, String... ids) throws Exception {
        UserManager um = getUserManager(r);
        Group g = (Group) um.getAuthorizable(GROUP_ID);
        for (String id : ids) {
            g.removeMember(um.getAuthorizable(id));
        }
        r.commit();
    }
}
