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
package org.apache.jackrabbit.oak.security.authorization.permission;

import java.security.Principal;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;
import java.util.Set;
import java.util.stream.Collectors;

import com.google.common.base.Strings;
import org.apache.jackrabbit.commons.iterator.AbstractLazyIterator;
import org.apache.jackrabbit.oak.api.Tree;
import org.apache.jackrabbit.oak.spi.security.ConfigurationParameters;
import org.apache.jackrabbit.oak.spi.security.principal.PrincipalImpl;
import org.jetbrains.annotations.NotNull;

class InvertedPermissionEntryProvider implements PermissionEntryProvider {

    /**
     * The set of principal names for which this {@code PermissionEntryProvider}
     * has been created.
     */
    private final Set<Principal> principals;

    private final PermissionStore store;

    InvertedPermissionEntryProvider(@NotNull PermissionStore store, @NotNull Set<Principal> principals) {
        this.store = store;
        this.principals = principals;
    }

    private void init() {
    }

    // --------------------------------------------< PermissionEntryProvider
    // >---
    @Override
    public void flush() {
        init();
    }

    @Override
    @NotNull
    public Iterator<PermissionEntry> getEntryIterator(@NotNull EntryPredicate predicate) {
        return new EntryIterator(predicate);
    }

    @Override
    @NotNull
    public Collection<PermissionEntry> getEntries(@NotNull Tree accessControlledTree) {
        return getEntries(accessControlledTree.getPath());
    }

    // ------------------------------------------------------------< private
    // >---
    @NotNull
    private Collection<PermissionEntry> getEntries(@NotNull String path) {
        // TODO impossible to properly extract the principal info due to encoding in the store
        return store.loadByPath(path).stream()
                .filter(e -> e.getPrincipal() != null && principals.contains(new PrincipalImpl(e.getPrincipal())))
                .collect(Collectors.toList());
    }

    private final class EntryIterator extends AbstractLazyIterator<PermissionEntry> {

        private final EntryPredicate predicate;

        // the ordered permission entries at a given path in the hierarchy
        private Iterator<PermissionEntry> nextEntries = Collections.emptyIterator();

        // the next oak path for which to retrieve permission entries
        private String path;

        private EntryIterator(@NotNull EntryPredicate predicate) {
            this.predicate = predicate;
            this.path = Strings.nullToEmpty(predicate.getPath());
        }

        @Override
        protected PermissionEntry getNext() {
            PermissionEntry next = null;
            while (next == null) {
                if (nextEntries.hasNext()) {
                    PermissionEntry pe = nextEntries.next();
                    if (predicate.apply(pe)) {
                        next = pe;
                    }
                } else {
                    if (path == null) {
                        break;
                    }
                    nextEntries = getEntries(path).iterator();
                    path = PermissionUtil.getParentPathOrNull(path);
                }
            }
            return next;
        }
    }
}
