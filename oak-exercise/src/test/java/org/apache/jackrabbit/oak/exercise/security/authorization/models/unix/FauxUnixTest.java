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
import static org.apache.jackrabbit.JcrConstants.JCR_PRIMARYTYPE;
import static org.apache.jackrabbit.oak.api.Type.NAME;
import static org.apache.jackrabbit.oak.exercise.security.authorization.models.unix.FauxUnixAuthorizationHelper.chmod;
import static org.apache.jackrabbit.oak.exercise.security.authorization.models.unix.FauxUnixAuthorizationHelper.chown;
import static org.apache.jackrabbit.oak.plugins.tree.TreeUtil.getString;
import static org.apache.jackrabbit.oak.plugins.tree.TreeUtil.getStrings;
import static org.apache.jackrabbit.oak.spi.nodetype.NodeTypeConstants.NT_OAK_UNSTRUCTURED;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.util.UUID;

import javax.jcr.SimpleCredentials;

import org.apache.jackrabbit.api.security.user.User;
import org.apache.jackrabbit.oak.AbstractSecurityTest;
import org.apache.jackrabbit.oak.api.CommitFailedException;
import org.apache.jackrabbit.oak.api.ContentSession;
import org.apache.jackrabbit.oak.api.Root;
import org.apache.jackrabbit.oak.api.Tree;
import org.apache.jackrabbit.oak.exercise.security.authorization.models.unix.FauxUnixSimplePolicies.FauxUnixPolicy;
import org.apache.jackrabbit.oak.security.authorization.composite.CompositeAuthorizationConfiguration;
import org.apache.jackrabbit.oak.security.user.UserConfigurationImpl;
import org.apache.jackrabbit.oak.spi.security.ConfigurationParameters;
import org.apache.jackrabbit.oak.spi.security.SecurityProvider;
import org.apache.jackrabbit.oak.spi.security.authorization.AuthorizationConfiguration;
import org.apache.jackrabbit.oak.spi.security.authorization.permission.AggregatedPermissionProvider;
import org.apache.jackrabbit.oak.spi.security.authorization.permission.PermissionProvider;
import org.apache.jackrabbit.oak.spi.security.authorization.permission.Permissions;
import org.apache.jackrabbit.oak.spi.security.user.AuthorizableNodeName;
import org.apache.jackrabbit.oak.spi.security.user.UserAuthenticationFactory;
import org.apache.jackrabbit.oak.spi.security.user.UserConfiguration;
import org.apache.jackrabbit.oak.spi.security.user.UserConstants;
import org.apache.jackrabbit.oak.spi.security.user.action.AuthorizableActionProvider;
import org.junit.Ignore;
import org.junit.Test;

import com.google.common.collect.Iterables;

public class FauxUnixTest extends AbstractSecurityTest {

    private User u1;

    private User u2;

    private ContentSession s1;

    private ContentSession s2;

    protected ConfigurationParameters getSecurityConfigParameters() {
        AuthorizableActionProvider authorizableActionProvider = new FauxUnixAuthorizableActionProvider();
        AuthorizableNodeName authorizableNodeName = AuthorizableNodeName.DEFAULT;
        UserAuthenticationFactory userAuthenticationFactory = UserConfigurationImpl.getDefaultAuthenticationFactory();

        ConfigurationParameters userParams = ConfigurationParameters.of(
                ConfigurationParameters.of(UserConstants.PARAM_AUTHORIZABLE_ACTION_PROVIDER,
                        authorizableActionProvider),
                ConfigurationParameters.of(UserConstants.PARAM_AUTHORIZABLE_NODE_NAME, authorizableNodeName),
                ConfigurationParameters.of(UserConstants.PARAM_USER_AUTHENTICATION_FACTORY, userAuthenticationFactory));

        return ConfigurationParameters.of(UserConfiguration.NAME, userParams);
    }

    @Override
    protected SecurityProvider initSecurityProvider() {
        SecurityProvider sp = super.initSecurityProvider();

        FauxUnixAuthorizationConfiguration fauxUnix = new FauxUnixAuthorizationConfiguration();
        fauxUnix.setSecurityProvider(sp);
        fauxUnix.setRootProvider(getRootProvider());
        fauxUnix.setTreeProvider(getTreeProvider());

        CompositeAuthorizationConfiguration ac = (CompositeAuthorizationConfiguration) sp
                .getConfiguration(AuthorizationConfiguration.class);
        ac.setDefaultConfig(fauxUnix);

        return sp;
    }

    @Override
    public void before() throws Exception {
        super.before();

        u1 = newTestUser();
        u2 = newTestUser();
        s1 = login(new SimpleCredentials(u1.getID(), u1.getID().toCharArray()));
        s2 = login(new SimpleCredentials(u2.getID(), u2.getID().toCharArray()));

        // check user can read its own path
        assertTrue(s1.getLatestRoot().getTree(u1.getPath()).exists());
        assertTrue(s2.getLatestRoot().getTree(u2.getPath()).exists());

        // bootstap content
        Tree a = root.getTree("/").addChild("a");
        a.setProperty(JCR_PRIMARYTYPE, NT_OAK_UNSTRUCTURED, NAME);
        a.setProperty("aProp", "aValue");
        root.commit();

        // change owner of /a to s1
        String p1 = s1.getAuthInfo().getUserID();
        assertTrue(chown("/a", p1, getAccessControlManager(root)));
        root.commit();

        Root r1 = s1.getLatestRoot();
        a = r1.getTree("/a");
        Tree b = a.addChild("b");
        b.setProperty(JCR_PRIMARYTYPE, NT_OAK_UNSTRUCTURED, NAME);
        b.setProperty("bProp", "bValue");

        Tree c = b.addChild("c");
        c.setProperty(JCR_PRIMARYTYPE, NT_OAK_UNSTRUCTURED, NAME);
        c.setProperty("cProp", "cValue");
        r1.commit();

        root.refresh();
        assertEquals(p1, getString(root.getTree("/a"), FauxUnixAuthorizationConfiguration.REP_USER));
        assertTrue(Iterables.contains(getStrings(root.getTree("/a"), JCR_MIXINTYPES),
                FauxUnixAuthorizationConfiguration.MIX_REP_FAUX_UNIX));

        assertEquals(p1, getString(root.getTree("/a/b"), FauxUnixAuthorizationConfiguration.REP_USER));
        assertTrue(Iterables.contains(getStrings(root.getTree("/a/b"), JCR_MIXINTYPES),
                FauxUnixAuthorizationConfiguration.MIX_REP_FAUX_UNIX));

        assertEquals(p1, getString(root.getTree("/a/b/c"), FauxUnixAuthorizationConfiguration.REP_USER));
        assertTrue(Iterables.contains(getStrings(root.getTree("/a/b/c"), JCR_MIXINTYPES),
                FauxUnixAuthorizationConfiguration.MIX_REP_FAUX_UNIX));
    }

    @Override
    public void after() throws Exception {
        if (u1 != null) {
            u1.remove();
        }
        if (u2 != null) {
            u2.remove();
        }
        root.commit();
        super.after();
    }

    protected User newTestUser() throws Exception {
        String uid = "testUser|" + UUID.randomUUID();
        User testUser = getUserManager(root).createUser(uid, uid);
        root.commit();
        return testUser;
    }

    @Test
    public void testPolicies() throws Exception {
        FauxUnixPolicy fup = FauxUnixAuthorizationHelper.getPolicy("/a", getAccessControlManager(root));
        assertEquals(s1.getAuthInfo().getUserID(), fup.getOwner());

        FauxUnixPolicy fup1 = FauxUnixAuthorizationHelper.getPolicy("/a", getAccessControlManager(s1.getLatestRoot()));
        assertNotNull(fup1);

        FauxUnixPolicy fup2 = FauxUnixAuthorizationHelper.getPolicy("/a", getAccessControlManager(s2.getLatestRoot()));
        assertNull(fup2);
    }

    @Test
    public void testExists() throws Exception {
        Root r1 = s1.getLatestRoot();
        assertFalse(r1.getTree("/").exists());
        assertTrue(r1.getTree("/a").exists());
        assertTrue(r1.getTree("/a").hasProperty("aProp"));
        assertTrue(r1.getTree("/a/b").exists());
        assertTrue(r1.getTree("/a/b/c").exists());

        Root r2 = s2.getLatestRoot();
        assertFalse(r2.getTree("/").exists());
        assertFalse(r2.getTree("/a").exists());
        assertFalse(r2.getTree("/a/b").exists());
        assertFalse(r2.getTree("/a/b/c").exists());
    }

    @Test
    public void testSupported() throws Exception {
        Root r1 = s1.getLatestRoot();
        PermissionProvider p1 = getConfig(AuthorizationConfiguration.class).getPermissionProvider(r1, "",
                s1.getAuthInfo().getPrincipals());
        assertTrue(p1 instanceof AggregatedPermissionProvider);
        AggregatedPermissionProvider fp1 = (AggregatedPermissionProvider) p1;

        long s0 = fp1.supportedPermissions((Tree) null, null, Permissions.NODE_TYPE_MANAGEMENT);
        assertEquals(Permissions.NODE_TYPE_MANAGEMENT, s0);

        assertTrue(fp1.isGranted(r1.getTree("/a"), null, Permissions.WRITE));
        assertTrue(fp1.isGranted(r1.getTree("/a"), null, Permissions.NODE_TYPE_MANAGEMENT));
    }

    @Test
    public void testChown() throws Exception {
        Root r1 = s1.getLatestRoot();
        assertTrue(r1.getTree("/a/b").exists());
        assertTrue(r1.getTree("/a/b/c").exists());

        Root r2 = s2.getLatestRoot();
        assertFalse(r2.getTree("/a/b").exists());
        assertFalse(r2.getTree("/a/b/c").exists());

        // chown
        String p2 = s2.getAuthInfo().getUserID();
        r1 = s1.getLatestRoot();
        chown("/a/b", p2, getAccessControlManager(r1));
        r1.commit();

        r1 = s1.getLatestRoot();
        assertFalse(r1.getTree("/a/b").exists());
        assertTrue(r1.getTree("/a/b/c").exists());

        r2 = s2.getLatestRoot();
        assertTrue(r2.getTree("/a/b").exists());
        assertFalse(r2.getTree("/a/b/c").exists());
    }

    @Test
    public void testChmod() throws Exception {
        Root r1 = s1.getLatestRoot();
        assertTrue(r1.getTree("/a/b").exists());
        assertTrue(r1.getTree("/a/b/c").exists());

        Root r2 = s2.getLatestRoot();
        assertFalse(r2.getTree("/a/b").exists());
        assertFalse(r2.getTree("/a/b/c").exists());

        // allow 'other' read access
        r1 = s1.getLatestRoot();
        chmod("/a/b", "o=r--", getAccessControlManager(r1));
        r1.commit();

        r1 = s1.getLatestRoot();
        assertTrue(r1.getTree("/a/b").exists());
        assertTrue(r1.getTree("/a/b/c").exists());

        r2 = s2.getLatestRoot();
        assertTrue(r2.getTree("/a/b").exists());
        assertFalse(r2.getTree("/a/b/c").exists());
    }

    @Test
    public void testChanges() throws Exception {
        Root r1 = s1.getLatestRoot();
        r1.getTree("/a").setProperty("test", "t");
        r1.commit();

        Tree t = r1.getTree("/a").addChild("test");
        t.setProperty(JCR_PRIMARYTYPE, NT_OAK_UNSTRUCTURED, NAME);
        r1.commit();

        r1.getTree("/a/b").remove();
        r1.commit();
    }

    @Ignore
    @Test(expected = CommitFailedException.class)
    public void testCreateUserNonAdmin() throws Exception {

        // unix only allows admin user to perform admin tasks
        String p1 = s1.getAuthInfo().getUserID();

        // try to create a user with a non-admin session:
        //
        // 1st error:
        // need to allow write access to user root + intermediate paths (if any)
        //
        // javax.jcr.AccessDeniedException: Missing permission to create
        // intermediate authorizable folders.
        // org.apache.jackrabbit.oak.security.user.UserProvider.createFolderNodes(UserProvider.java:307)
        // org.apache.jackrabbit.oak.security.user.UserProvider.createAuthorizableNode(UserProvider.java:255)
        // org.apache.jackrabbit.oak.security.user.UserProvider.createUser(UserProvider.java:183)
        root.refresh();
        chown("/rep:security/rep:authorizables/rep:users", p1, getAccessControlManager(root));

        // 2nd error
        // node type tree is not readable - fixed it in the default model to
        // open certain paths to be readable by anyone
        //
        // javax.jcr.nodetype.NoSuchNodeTypeException: Node type rep:User does
        // not exist
        // org.apache.jackrabbit.oak.plugins.tree.TreeUtil.addChild(TreeUtil.java:210)
        // org.apache.jackrabbit.oak.security.user.UserProvider.createAuthorizableNode(UserProvider.java:269)
        // org.apache.jackrabbit.oak.security.user.UserProvider.createUser(UserProvider.java:183)

        // 3rd error
        // isGranted(/rep:security/rep:authorizables/rep:users/x/xy/xyzUser%7Cf90ada90-cc62-498b-bc96-61d67d1e6079,
        // [USER_MANAGEMENT])=false
        //
        // org.apache.jackrabbit.oak.api.CommitFailedException: OakAccess0000:
        // Access
        // denied(/rep:security/rep:authorizables/rep:users/x/xy/xyzUser%7C87b1b08e-f0d6-4096-ae92-ef594465c71c)
        // org.apache.jackrabbit.oak.security.authorization.permission.PermissionValidator.checkPermissions(PermissionValidator.java:210)
        root.commit();

        Root r1 = s1.getLatestRoot();
        r1.refresh();
        String uid = "xyzUser|" + UUID.randomUUID();
        getUserManager(r1).createUser(uid, uid);
        r1.commit();
    }
}
