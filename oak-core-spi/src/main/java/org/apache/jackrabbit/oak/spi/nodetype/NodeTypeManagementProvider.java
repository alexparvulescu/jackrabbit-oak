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
package org.apache.jackrabbit.oak.spi.nodetype;

import java.io.InputStream;

import javax.annotation.Nonnull;

import org.apache.jackrabbit.oak.api.Root;
import org.apache.jackrabbit.oak.namepath.NamePathMapper;
import org.osgi.annotation.versioning.ProviderType;

@ProviderType
public interface NodeTypeManagementProvider {

    @Nonnull
    NodeTypeManager getReadOnlyNodeTypeManager(@Nonnull Root root, @Nonnull NamePathMapper namePathMapper);

    //@Nonnull
    //Predicate<NodeState> getNodeTypePredicate(@Nonnull NodeState node, @Nonnull String... names);

    //@Nonnull
    //EditorProvider getEditorProvider(boolean strict);

    void registerNodeTypes(@Nonnull Root root, @Nonnull InputStream input, @Nonnull String systemId);

}