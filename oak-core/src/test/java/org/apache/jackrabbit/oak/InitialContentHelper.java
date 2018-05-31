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
package org.apache.jackrabbit.oak;

import org.apache.jackrabbit.oak.plugins.memory.MemoryNodeStore;
import org.apache.jackrabbit.oak.plugins.name.NamespaceEditorProvider;
import org.apache.jackrabbit.oak.plugins.nodetype.TypeEditorProvider;
import org.apache.jackrabbit.oak.spi.commit.CompositeEditorProvider;
import org.apache.jackrabbit.oak.spi.commit.EditorHook;
import org.apache.jackrabbit.oak.spi.lifecycle.CompositeInitializer;
import org.apache.jackrabbit.oak.spi.lifecycle.RepositoryInitializer;
import org.apache.jackrabbit.oak.spi.security.authorization.OpenAuthorizationConfiguration;
import org.apache.jackrabbit.oak.spi.state.NodeState;
import org.apache.jackrabbit.oak.spi.state.NodeStore;

public class InitialContentHelper {

    private InitialContentHelper() {
    }

    public static final NodeState INITIAL_CONTENT = createInitialContent();

    private static NodeState createInitialContent() {
        NodeStore store = new MemoryNodeStore();
        EditorHook hook = new EditorHook(
                new CompositeEditorProvider(new NamespaceEditorProvider(), new TypeEditorProvider()));

        // needed because the 'rep:privileges' node does not exist so it
        // conflicts with the jcr:system definition
        OpenAuthorizationConfiguration oac = new OpenAuthorizationConfiguration();
        RepositoryInitializer ris = new CompositeInitializer(
                new InitialContent() , oac.getRepositoryInitializer());
        OakInitializer.initialize(store, ris, hook);
        return store.getRoot();
    }
}
