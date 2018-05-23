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
package org.apache.jackrabbit.oak.spi.identifier;

import javax.annotation.CheckForNull;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.apache.jackrabbit.oak.api.PropertyState;
import org.apache.jackrabbit.oak.api.PropertyValue;
import org.apache.jackrabbit.oak.api.Tree;

public interface IdentifierManager {

    /**
     * Return the identifier of a tree.
     *
     * @param tree  a tree
     * @return identifier of {@code tree}
     */
    @Nonnull
    String getIdentifierFromTree(Tree tree);

    /**
     * The possibly non existing tree identified by the specified {@code identifier} or {@code null}.
     *
     * @param identifier The identifier of the tree such as exposed by {@link #getIdentifier(Tree)}
     * @return The tree with the given {@code identifier} or {@code null} if no
     *         such tree exists.
     */
    @CheckForNull
    Tree getTree(@Nonnull String identifier);

    /**
     * The path of the tree identified by the specified {@code identifier} or {@code null}.
     *
     * @param identifier The identifier of the tree such as exposed by {@link #getIdentifier(Tree)}
     * @return The path of the tree with the given {@code identifier} or {@code null} if no
     *         such tree exists or if the tree is not accessible.
     */
    @CheckForNull
    String getPath(@Nonnull String identifier);

    /**
     * Returns the path of the tree references by the specified (weak)
     * reference {@code PropertyState}.
     *
     * @param referenceValue A (weak) reference value.
     * @return The tree with the given {@code identifier} or {@code null} if no
     *         such tree exists or isn't accessible to the content session.
     */
    @CheckForNull
    String getPath(@Nonnull PropertyState referenceValue);

    /**
     * Returns the path of the tree references by the specified (weak)
     * reference {@code PropertyState}.
     *
     * @param referenceValue A (weak) reference value.
     * @return The tree with the given {@code identifier} or {@code null} if no
     *         such tree exists or isn't accessible to the content session.
     */
    @CheckForNull
    String getPath(@Nonnull PropertyValue referenceValue);

    /**
     * Searches all reference properties to the specified {@code tree} that match
     * the given name and node type constraints.
     *
     * @param weak          if {@code true} only weak references are returned. Otherwise only
     *                      hard references are returned.
     * @param tree          The tree for which references should be searched.
     * @param propertyName  A name constraint for the reference properties;
     *                      {@code null} if no constraint should be enforced.
     * @return A set of oak paths of those reference properties referring to the
     *         specified {@code tree} and matching the constraints.
     */
    @Nonnull
    Iterable<String> getReferences(boolean weak, @Nonnull Tree tree, @Nullable final String propertyName);

    /**
     * Searches all reference properties to the specified {@code tree} that match
     * the given {@code propertyName} and the specified, mandatory node type
     * constraint ({@code ntName}). In contrast to {@link #getReferences} this
     * method requires all parameters to be specified, which eases the handling
     * of the result set and doesn't require the trees associated with the
     * result set to be resolved.
     *
     * @param tree The tree for which references should be searched.
     * @param propertyName The name of the reference properties.
     * @param ntName The node type name to be used for the query.
     * @param weak if {@code true} only weak references are returned. Otherwise on hard references are returned.
     * @return A set of oak paths of those reference properties referring to the
     *         specified {@code tree} and matching the constraints.
     */
    @Nonnull
    public Iterable<String> getReferences(@Nonnull Tree tree, @Nonnull final String propertyName,
                                          @Nonnull String ntName, boolean weak);
}