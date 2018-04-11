package org.apache.jackrabbit.oak.exercise.security.authorization.models.unix;

import static com.google.common.base.Preconditions.checkNotNull;
import static org.apache.jackrabbit.JcrConstants.JCR_PRIMARYTYPE;
import static org.apache.jackrabbit.oak.api.Type.NAME;
import static org.apache.jackrabbit.oak.spi.nodetype.NodeTypeConstants.NT_OAK_UNSTRUCTURED;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.security.Principal;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.jcr.AccessDeniedException;
import javax.jcr.security.AccessControlManager;

import org.apache.jackrabbit.api.security.JackrabbitAccessControlList;
import org.apache.jackrabbit.commons.jackrabbit.authorization.AccessControlUtils;
import org.apache.jackrabbit.oak.AbstractSecurityTest;
import org.apache.jackrabbit.oak.api.ContentSession;
import org.apache.jackrabbit.oak.api.Root;
import org.apache.jackrabbit.oak.api.Tree;
import org.apache.jackrabbit.oak.security.authorization.composite.CompositeAuthorizationConfiguration;
import org.apache.jackrabbit.oak.spi.security.SecurityProvider;
import org.apache.jackrabbit.oak.spi.security.authorization.AuthorizationConfiguration;
import org.junit.Test;

public class FauxUnixTest extends AbstractSecurityTest {

    private ContentSession testSession;

    private ContentSession testSession2;

    @Override
    protected SecurityProvider initSecurityProvider() {
        SecurityProvider sp = super.initSecurityProvider();

        CompositeAuthorizationConfiguration ac = (CompositeAuthorizationConfiguration) sp
                .getConfiguration(AuthorizationConfiguration.class);

        AuthorizationConfiguration fauxUnix = new FauxUnixAuthorizationConfiguration();
        ac.setDefaultConfig(fauxUnix);
        return sp;
    }

    @Override
    public void before() throws Exception {
        super.before();
        testSession = createTestSession();
        Principal testPrincipal = testSession.getAuthInfo().getPrincipals().iterator().next();

        Tree rootNode = root.getTree("/");
        Tree a = addChild(rootNode, "a", NT_OAK_UNSTRUCTURED, testPrincipal.getName());
        a.setProperty("aProp", "aValue");
        Tree b = addChild(a, "b", NT_OAK_UNSTRUCTURED, testPrincipal.getName());
        b.setProperty("bProp", "bValue");
        Tree bb = addChild(a, "bb", NT_OAK_UNSTRUCTURED, testPrincipal.getName());
        bb.setProperty("bbProp", "bbValue");
        Tree c = addChild(b, "c", NT_OAK_UNSTRUCTURED, testPrincipal.getName());
        c.setProperty("cProp", "cValue");

        root.commit();
    }

    public static Tree addChild(@Nonnull Tree tree, @Nonnull String childName, @Nonnull String primaryTypeName,
            String userId) throws AccessDeniedException {
        Tree child = tree.addChild(childName);
        if (!child.exists()) {
            throw new AccessDeniedException();
        }
        child.setProperty(JCR_PRIMARYTYPE, primaryTypeName, NAME);
        child.setProperty(FauxUnixAuthorizationConfiguration.REP_USER, userId);
        child.setProperty(FauxUnixAuthorizationConfiguration.REP_PERMISSIONS,
                FauxUnixAuthorizationConfiguration.DEFAULT_PERMISSIONS);
        return child;
    }

    @Test
    public void testReadPermission() {
        Root testRoot = testSession.getLatestRoot();

        assertFalse(testRoot.getTree("/").exists());
        assertTrue(testRoot.getTree("/a/b").exists());
        assertTrue(testRoot.getTree("/a/b/c").exists());
    }
}
