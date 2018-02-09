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
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

import javax.annotation.Nonnull;

import org.apache.jackrabbit.oak.commons.LongUtils;
import org.apache.jackrabbit.oak.spi.security.ConfigurationParameters;

/**
 * {@code PermissionEntryCache} caches the permission entries of principals.
 * The cache is held locally for each session and contains a version of the principal permission
 * entries of the session that read them last.
 *
 * TODO:
 * - report cache usage metrics
 * - limit size of local caches based on ppe sizes. the current implementation loads all ppes. this can get a memory
 *   problem, as well as a performance problem for principals with many entries. principals with many entries must
 *   fallback to the direct store.load() methods when providing the entries. if those principals with many entries
 *   are used often, they might get elected to live in the global cache; memory permitting.
 */
class PermissionEntryCache {

    private static final long DEFAULT_SIZE = 250;

    // private final Map<String, PrincipalPermissionEntries> entries = new HashMap<String, PrincipalPermissionEntries>();

    // <PrincipalsArray -> <>>
    private final Map<Set<String>, Map<String, Collection<PermissionEntry>>> cache = new HashMap<>();

    private final PermissionStore store;
    private final long maxSize;

    boolean isLazy = false;

    PermissionEntryCache( @Nonnull PermissionStore store,  @Nonnull ConfigurationParameters options) {
        this.store = store;
        this.maxSize = options.getConfigValue(PermissionEntryProviderImpl.EAGER_CACHE_SIZE_PARAM, DEFAULT_SIZE);
    }

    Set<String> init(@Nonnull Set<String> allPrincipals) {

        Set<String> existingNames = new HashSet<String>();
        long cnt = 0;
        for (String name : allPrincipals) {
            long n = store.getNumEntries(name, maxSize);
            /*
            if cache.getNumEntries (n) returns a number bigger than 0, we
            remember this principal name int the 'existingNames' set
            */
            if (n > 0) {
                existingNames.add(name);
            }
            /*
            Calculate the total number of permission entries (cnt) defined for the
            given set of principals in order to be able to determine if the cache
            should be loaded upfront.
            Note however that cache.getNumEntries (n) may return Long.MAX_VALUE
            if the underlying implementation does not know the exact value, and
            the child node count is higher than maxSize (see OAK-2465).
            */                        
            if (cnt < Long.MAX_VALUE) {
                if (Long.MAX_VALUE == n) {
                    cnt = Long.MAX_VALUE;
                } else {
                    cnt = LongUtils.safeAdd(cnt, n);
                }
            }
        }

        if (cnt > 0 && cnt < maxSize) {
            // the total number of entries is smaller that maxSize, so we can
            // cache all entries for all principals having any entries right
            // away
            Map<String, Collection<PermissionEntry>> all = new HashMap<>();
            cache.put(existingNames, all);
            init(existingNames, all);
            return existingNames; // cached
        }

        if (existingNames.isEmpty()) {
            return null; // noop
        }
        isLazy = true;
        cache.put(existingNames, new HashMap<>());
        return existingNames; // lazy load as needed
    }

    private void init(@Nonnull Set<String> key, Map<String, Collection<PermissionEntry>> all) {
        for (String name : key) {
            PrincipalPermissionEntries ppe = store.load(name);

            for (String p : ppe.getEntries().keySet()) {
                Collection<PermissionEntry> byPath = all.get(p);
                if (byPath == null) {
                    byPath = new TreeSet<>();
                    all.put(p, byPath);
                }
                byPath.addAll(ppe.getEntries().get(p));
            }
        }
    }

    @Nonnull
    Collection<PermissionEntry> load(@Nonnull Set<String> principals, @Nonnull String path) {
        if (!isLazy) { // cache is fully loaded
            return cache.get(principals).get(path);
        }

        // TODO cache can overflow
        // - how to optim path loading
        Collection<PermissionEntry> pes = cache.get(principals).get(path);
        if (pes == null) {
            pes = new TreeSet<>();
            for (String p : principals) {
                store.load(pes, p, path);
            }
            cache.get(principals).put(path, pes);
        }
        return pes;
    }

    void flush(@Nonnull Set<String> principals) {
        cache.remove(principals);
    }
}