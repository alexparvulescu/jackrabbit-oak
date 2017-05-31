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
package org.apache.jackrabbit.oak.security.authorization.composite;

import java.lang.reflect.Field;
import java.util.Arrays;

import javax.annotation.Nonnull;

import org.apache.jackrabbit.oak.AbstractSecurityTest;
import org.apache.jackrabbit.oak.api.Root;
import org.apache.jackrabbit.oak.api.Tree;
import org.apache.jackrabbit.oak.plugins.nodetype.NodeTypeConstants;
import org.apache.jackrabbit.oak.plugins.tree.RootFactory;
import org.apache.jackrabbit.oak.plugins.tree.TreeUtil;
import org.apache.jackrabbit.oak.plugins.tree.impl.ImmutableTree;
<<<<<<< HEAD
import org.apache.jackrabbit.oak.security.authorization.composite.CompositeAuthorizationConfiguration.CompositionType;
=======
import org.apache.jackrabbit.oak.security.authorization.composite.CompositePermissionProvider.CheckType;
>>>>>>> 26afaf4a1e... wip, rebase on top of oak-6356
import org.apache.jackrabbit.oak.spi.security.Context;
import org.apache.jackrabbit.oak.spi.security.authorization.permission.AggregatedPermissionProvider;
import org.apache.jackrabbit.oak.spi.security.authorization.permission.TreePermission;
import org.apache.jackrabbit.oak.spi.state.NodeState;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;

public class CompositeTreePermissionTest extends AbstractSecurityTest {

    //TODO 'OR' impl?
    private Root readOnlyRoot;
    private ImmutableTree rootTree;

    private AggregatedPermissionProvider fullScopeProvider;

    @Override
    public void before() throws Exception {
        super.before();

        Tree rootNode = root.getTree("/");
        TreeUtil.addChild(rootNode, "test", NodeTypeConstants.NT_OAK_UNSTRUCTURED);
        root.commit();

        readOnlyRoot = RootFactory.createReadOnlyRoot(root);
        rootTree = (ImmutableTree) readOnlyRoot.getTree("/");

        fullScopeProvider = new FullScopeProvider(readOnlyRoot);
    }

    @Override
    public void after() throws Exception {
        try {
            root.refresh();
            root.getTree("/test").remove();
            root.commit();
        } finally {
            super.after();
        }
    }

<<<<<<< HEAD
    private TreePermission createRootTreePermission(AggregatedPermissionProvider... providers) {
        return new CompositePermissionProvider(readOnlyRoot, Arrays.asList(providers), Context.DEFAULT, CompositionType.AND)
=======
    private TreePermission createRootTreePermissionAND(AggregatedPermissionProvider... providers) {
        return new CompositePermissionProvider(readOnlyRoot, 
                Arrays.asList(providers), 
                Context.DEFAULT, CheckType.AND)
>>>>>>> 26afaf4a1e... wip, rebase on top of oak-6356
                .getTreePermission(rootTree, TreePermission.EMPTY);
    }

    private static void assertCompositeTreePermission(boolean expected, @Nonnull TreePermission tp) {
        assertEquals(expected, tp instanceof CompositeTreePermission);
    }

    @Test
    public void testEmpty() {
        TreePermission rootTp = createRootTreePermissionAND();
        assertSame(TreePermission.EMPTY, rootTp);
        assertFalse(rootTp.canRead());
    }

    @Test
    public void testSingle() {
        Class<? extends TreePermission> expected = fullScopeProvider.getTreePermission(rootTree, TreePermission.EMPTY).getClass();

        TreePermission rootTp = createRootTreePermissionAND(fullScopeProvider);
        assertCompositeTreePermission(false, rootTp);
        assertEquals(expected, rootTp.getClass());

        TreePermission testTp = rootTp.getChildPermission("test", rootTree.getChild("test").getNodeState());
        assertEquals(expected, testTp.getClass());
    }

    @Test
    public void testMultiple() {
        TreePermission rootTp = createRootTreePermissionAND(fullScopeProvider, fullScopeProvider);
        assertCompositeTreePermission(true, rootTp);

        TreePermission testTp = rootTp.getChildPermission("test", rootTree.getChild("test").getNodeState());
        assertCompositeTreePermission(true, testTp);
    }

    @Test
    public void testMultipleNoRecurse() {
        TreePermission rootTp = createRootTreePermissionAND(new NoScopeProvider(root), new NoScopeProvider(root));
        assertCompositeTreePermission(true, rootTp);

        assertSame(TreePermission.EMPTY, rootTp.getChildPermission("test", rootTree.getChild("test").getNodeState()));
    }

    @Test
    public void testMultipleToSingle() {
        TreePermission rootTp = createRootTreePermissionAND(fullScopeProvider, new NoScopeProvider(root), new NoScopeProvider(root));
        assertCompositeTreePermission(true, rootTp);

        NodeState childState = rootTree.getChild("test").getNodeState();
        TreePermission testTp = rootTp.getChildPermission("test", childState);
        TreePermission expected = fullScopeProvider.getTreePermission(rootTree, TreePermission.EMPTY).getChildPermission("test", childState);
        assertEquals(expected.getClass(), testTp.getClass());
    }

    @Test
    public void testCanRead() throws Exception {
        TreePermission rootTp = createRootTreePermissionAND(fullScopeProvider, fullScopeProvider);

        Field f = CompositeTreePermission.class.getDeclaredField("canRead");
        f.setAccessible(true);

        Object canRead = f.get(rootTp);
        assertNull(canRead);

        rootTp.canRead();

        canRead = f.get(rootTp);
        assertNotNull(canRead);
    }

    @Test
    public void testParentNoRecourse() throws Exception {
        TreePermission rootTp = createRootTreePermissionAND(new NoScopeProvider(root));
        assertSame(TreePermission.NO_RECOURSE, rootTp);
    }
}