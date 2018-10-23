package org.apache.jackrabbit.oak.benchmark.authorization;

import static javax.jcr.security.Privilege.JCR_READ;
import static org.apache.jackrabbit.commons.jackrabbit.authorization.AccessControlUtils.addAccessControlEntry;
import static org.junit.Assert.assertFalse;

import javax.jcr.Node;
import javax.jcr.Session;
import javax.jcr.SimpleCredentials;
import javax.jcr.security.Privilege;

import org.apache.jackrabbit.api.JackrabbitSession;
import org.apache.jackrabbit.api.security.user.Group;
import org.apache.jackrabbit.api.security.user.User;
import org.apache.jackrabbit.api.security.user.UserManager;
import org.apache.jackrabbit.oak.benchmark.AbstractTest;
import org.apache.jackrabbit.oak.spi.security.principal.EveryonePrincipal;
import org.apache.jackrabbit.oak.spi.security.principal.PrincipalImpl;

public class CanReadNonExisting extends AbstractTest {

    static final String uid = "u0";

    static final int contentNodes = 10000;
    
    @Override
    public void beforeSuite() throws Exception {
        boolean USE_MAP = Boolean.getBoolean("oak.PrincipalPermissionEntries.map");
        int MAX = Integer.getInteger("oak.PrincipalPermissionEntries", -1);
        System.out.println("setup: use map: " + USE_MAP + ", max: " + MAX);

        super.beforeSuite();

        //PermissionEntryProviderImpl#DEFAULT_SIZE + delta
        int groupCount = 255;

        Session s = loginAdministrative();
        addAccessControlEntry(s, "/", EveryonePrincipal.getInstance(), new String[] { Privilege.JCR_READ }, false);

        // PermissionCacheBuilder#MAX_PATHS_SIZE + 1
        int extraPolicies = 11;
        Node extras = s.getNode("/").addNode("extras");
        for (int i = 0; i < extraPolicies; i++) {
            extras.addNode(i + "");
        }
        s.save();
        //System.out.println("created /extras/*");

        try {
            UserManager userManager = ((JackrabbitSession) s).getUserManager();

            User eye = userManager.createUser("eye", "eye");
            
            
            
            User u = userManager.createUser(uid, uid);
            addAccessControlEntry(s, u.getPath(), u.getPrincipal(), new String[] { JCR_READ }, true);
            for (int i = 0; i < extraPolicies; i++) {
                addAccessControlEntry(s, "/extras/" + i, u.getPrincipal(), new String[] { JCR_READ }, true);
            }
            //System.out.println("created user");

            for (int i = 1; i <= groupCount; i++) {
                Group g = userManager.createGroup(new PrincipalImpl("g" + i));
                g.addMember(u);
                addAccessControlEntry(s, g.getPath(), g.getPrincipal(), new String[] { JCR_READ }, true);
                for (int j = 0; j < extraPolicies; j++) {
                    addAccessControlEntry(s, "/extras/" + j, g.getPrincipal(), new String[] { JCR_READ }, true);
                }
                s.save();
                //System.out.println("created group #" + i + "/" + groupCount);
            }

            Node content = s.getNode("/").addNode("content");
            for (int i = 0; i < contentNodes; i++) {
                String p = content.addNode(i + "").getPath();
                addAccessControlEntry(s, p, eye.getPrincipal(), new String[] { JCR_READ }, true);
            }
            s.save();

        } finally {
            s.save();
            s.logout();
        }
        System.out.println("setup done.");
    }

    @Override
    public void runTest() throws Exception {
        Session s = null;

        try {

            s = login(new SimpleCredentials(uid, uid.toCharArray()));
            for (int i = 0; i < contentNodes; i++) {
                assertFalse(s.nodeExists("/content/" + i));
            }

        } finally {
            if (s != null) {
                s.logout();
            }
        }
    }

    protected void afterSuite() throws Exception {
        //System.out.println("done!");
    }

    @Override
    protected void afterTest() throws Exception {
        //System.out.println("done test!");
    }
}
