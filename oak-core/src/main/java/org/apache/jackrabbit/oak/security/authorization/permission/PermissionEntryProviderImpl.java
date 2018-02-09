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

import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;
import java.util.Set;

import javax.annotation.Nonnull;

import org.apache.jackrabbit.commons.iterator.AbstractLazyIterator;
import org.apache.jackrabbit.oak.api.Tree;
import org.apache.jackrabbit.oak.spi.security.ConfigurationParameters;

import com.google.common.base.Strings;

class PermissionEntryProviderImpl implements PermissionEntryProvider {

    public static final String EAGER_CACHE_SIZE_PARAM = "eagerCacheSize";

    /**
     * The set of principal names for which this {@code PermissionEntryProvider}
     * has been created.
     */
    private final Set<String> principalNames;

    private Set<String> principals;

    private final PermissionEntryCache cache;

    private boolean noop;

    PermissionEntryProviderImpl(@Nonnull PermissionStore store, @Nonnull PermissionEntryCache cache,
            @Nonnull Set<String> principalNames, @Nonnull ConfigurationParameters options) {
        this.cache = cache;
        this.principalNames = principalNames;
        init();
    }

    private void init() {
        principals = cache.init(principalNames);
        this.noop = principals == null;
    }

    private String logName() {
        return this.toString().replace("org.apache.jackrabbit.oak.security.authorization.permission.", "");
    }

    //--------------------------------------------< PermissionEntryProvider >---
    @Override
    public void flush() {
        cache.flush(principals);
        init();
    }

    @Override
    @Nonnull
    public Iterator<PermissionEntry> getEntryIterator(@Nonnull EntryPredicate predicate) {
        if (noop) {
            return Collections.emptyIterator();
        } else {
            return new EntryIterator(predicate);
        }
    }

    @Override
    @Nonnull
    public Collection<PermissionEntry> getEntries(@Nonnull Tree accessControlledTree) {
        // TODO removed accessControlledTree.hasChild(AccessControlConstants.REP_POLICY)
        if (noop) {
            return Collections.emptyList();
        } else {
            return cache.load(principals, accessControlledTree.getPath());
        }
    }

    //------------------------------------------------------------< private >---

    @Nonnull
    private Collection<PermissionEntry> getEntries(@Nonnull String path) {
        if (noop) {
            return Collections.emptyList();
        } else {
            return cache.load(principals, path);
        }
    }

    private final class EntryIterator extends AbstractLazyIterator<PermissionEntry> {

        private final EntryPredicate predicate;

        // the ordered permission entries at a given path in the hierarchy
        private Iterator<PermissionEntry> nextEntries = Collections.emptyIterator();

        // the next oak path for which to retrieve permission entries
        private String path;

        private EntryIterator(@Nonnull EntryPredicate predicate) {
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