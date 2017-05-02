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
package org.apache.jackrabbit.oak.security.user;

import static org.apache.jackrabbit.oak.api.Type.NAME;

import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.function.Function;

import javax.annotation.Nonnull;
import javax.jcr.RepositoryException;

import org.apache.jackrabbit.JcrConstants;
import org.apache.jackrabbit.oak.api.PropertyState;
import org.apache.jackrabbit.oak.api.Tree;
import org.apache.jackrabbit.oak.api.Type;
import org.apache.jackrabbit.oak.plugins.memory.PropertyBuilder;
import org.apache.jackrabbit.oak.plugins.tree.TreeUtil;
import org.apache.jackrabbit.oak.spi.security.user.UserConstants;

import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Iterators;
import com.google.common.collect.Lists;
import com.google.common.collect.Maps;
import com.google.common.collect.Sets;

/**
 * @see MembershipProvider to more details.
 */
public class MembershipWriter {

    public static final int DEFAULT_MEMBERSHIP_THRESHOLD = 100;

    private final WriterStrategy writer;

    public MembershipWriter(boolean useTreeWriter) {
        if (useTreeWriter) {
            writer = new TreeWriter();
        } else {
            writer = new ListWriter();
        }
    }

    /**
     * Sets the size of the membership threshold after which a new overflow node is created.
     */
    public void setMembershipSizeThreshold(int membershipSizeThreshold) {
        writer.setMembershipSizeThreshold(membershipSizeThreshold);
    }

    /**
     * Adds a new member to the given {@code groupTree}.
     *
     * @param groupTree the group to add the member to
     * @param memberContentId the id of the new member
     * @return {@code true} if the member was added
     * @throws RepositoryException if an error occurs
     */
    boolean addMember(Tree groupTree, String memberContentId) throws RepositoryException {
        Map<String, String> m = Maps.newHashMapWithExpectedSize(1);
        m.put(memberContentId, "-");
        return addMembers(groupTree, m).isEmpty();
    }

    /**
     * Adds a new member to the given {@code groupTree}.
     *
     * @param groupTree the group to add the member to
     * @param memberIds the ids of the new members as map of 'contentId':'memberId'
     * @return the set of member IDs that was not successfully processed.
     * @throws RepositoryException if an error occurs
     */
    Set<String> addMembers(@Nonnull Tree groupTree, @Nonnull Map<String, String> memberIds) throws RepositoryException {
        return writer.addMembers(groupTree, memberIds);
    }

    /**
     * Removes the member from the given group.
     *
     * @param groupTree group to remove the member from
     * @param memberContentId member to remove
     * @return {@code true} if the member was removed.
     */
    boolean removeMember(@Nonnull Tree groupTree, @Nonnull String memberContentId) {
        Map<String, String> m = Maps.newHashMapWithExpectedSize(1);
        m.put(memberContentId, "-");
        return removeMembers(groupTree, m).isEmpty();
    }

    /**
     * Removes the members from the given group.
     *
     * @param groupTree group to remove the member from
     * @param memberIds Map of 'contentId':'memberId' of all members that need to be removed.
     * @return the set of member IDs that was not successfully processed.
     */
    Set<String> removeMembers(@Nonnull Tree groupTree, @Nonnull Map<String, String> memberIds) {
        return writer.removeMembers(groupTree, memberIds);
    }

    private static interface WriterStrategy {

        void setMembershipSizeThreshold(int membershipSizeThreshold);

        Set<String> addMembers(@Nonnull Tree groupTree, @Nonnull Map<String, String> memberIds)
                throws RepositoryException;

        Set<String> removeMembers(@Nonnull Tree groupTree, @Nonnull Map<String, String> memberIds);

    }

    private static class TreeWriterLeaf {

        Tree t;
        int level;
        boolean load;

        TreeWriterLeaf(Tree t, boolean load, int level) {
            this.t = t;
            this.level = level;
            this.load = load;
        }

        @Override
        public String toString() {
            return "TreeWriterLeaf [t=" + t + ", level=" + level + "]";
        }

    }

     static class TreeWriter implements WriterStrategy {

        private int membershipSizeThreshold = DEFAULT_MEMBERSHIP_THRESHOLD;

        // a132cbbd-6a2c-3981-965a-239e22fba6c7
        private static int MAX_LEVEL = 35;

        public void setMembershipSizeThreshold(int membershipSizeThreshold) {
            this.membershipSizeThreshold = membershipSizeThreshold;
        }

        @Override
        public Set<String> addMembers(@Nonnull Tree groupTree, final @Nonnull Map<String, String> memberIds)
                throws RepositoryException {
            Set<String> failed = new HashSet<String>();

            List<String> keys = Lists.newArrayList(memberIds.keySet());
            if (keys.size() > 1) {
                Collections.sort(keys);
            }

            TreeWriterLeaf location = new TreeWriterLeaf(groupTree, keys.size() > 1, -1);
            for (String key : keys) {
                String mid = memberIds.remove(key);
                if (mid == null) {
                    continue;
                }
                if (location.level >= 0) {
                    location = walkUp(location, key);
                }

                Function<String, Boolean> onProperty = new Function<String, Boolean>() {

                    @Override
                    public Boolean apply(String k) {
                        String v = memberIds.remove(k);
                        if (v != null) {
                            failed.add(v);
                        }
                        return !memberIds.isEmpty();
                    }
                };

                if (!addMember(key, location, membershipSizeThreshold, MAX_LEVEL, onProperty)) {
                    failed.add(mid);
                }
                if (memberIds.isEmpty()) {
                    break;
                }
            }
            return failed;
        }

        static TreeWriterLeaf walkUp(TreeWriterLeaf location, String key) {
            Tree t = location.t;
            int level = location.level;

            if (level >= 0 && !idToKey(key, level).equals(t.getName())) {
                if (level == 0) {
                    t = t.getParent();
                }
                TreeWriterLeaf nl = new TreeWriterLeaf(t.getParent(), true, level - 1);
                return walkUp(nl, key);
            }
            return location;
        }

        static boolean addMember(String uuid, TreeWriterLeaf location, int threshold, int maxLevel,
                Function<String, Boolean> onProperty) {
            Tree t = location.t;
            int level = location.level;

            // if property exists, we're sure this is a leaf
            PropertyState refs = t.getProperty(UserConstants.REP_MEMBERS);
            if (refs != null) {

                Set<String> newVals = getValues(refs.getValue(Type.WEAKREFERENCES), uuid, onProperty, location);
                if (newVals == null) {
                    return false;
                }
                newVals.add(uuid);

                if (newVals.size() <= threshold || level >= maxLevel) {
                    setRepMembers(t, newVals);
                    return true;

                } else {
                    // merge & split
                    t.removeProperty(UserConstants.REP_MEMBERS);
                    if (level == -1) {
                        t = t.addChild(UserConstants.REP_MEMBERS_LIST);
                        level++;
                    }
                    // change node type from 'refs' to 'ref list'
                    t.setProperty(JcrConstants.JCR_PRIMARYTYPE, UserConstants.NT_REP_MEMBER_REFERENCES_LIST, NAME);

                    Map<String, Set<String>> groupped = groupByKey(newVals, level);
                    for (Entry<String, Set<String>> e : groupped.entrySet()) {
                        Tree c = t.addChild(e.getKey());
                        c.setProperty(JcrConstants.JCR_PRIMARYTYPE, UserConstants.NT_REP_MEMBER_REFERENCES, NAME);
                        // this can overflow the threshold
                        setRepMembers(c, e.getValue());
                    }
                    location.t = t.getChild(idToKey(uuid, level));
                    location.level = level;
                    return true;
                }

            } else if (isLeafType(t, level)) {
                setRepMembers(t, ImmutableSet.of(uuid));
                location.load = false;
                return true;

            } else {
                // continue going down the tree
                if (level == -1) {
                    t = getOrAdd(t, UserConstants.REP_MEMBERS_LIST, UserConstants.NT_REP_MEMBER_REFERENCES_LIST);
                }
                level++;
                String key = idToKey(uuid, level);
                Tree c = getOrAdd(t, key, UserConstants.NT_REP_MEMBER_REFERENCES);

                location.t = c;
                location.level = level;
                location.load = true;

                return addMember(uuid, location, threshold, maxLevel, onProperty);
            }
        }

        private static Set<String> getValues(Iterable<String> refs, String uuid, Function<String, Boolean> onProperty,
                TreeWriterLeaf location) {
            if (location.load) {
                // eager load, process callback and lookup separately
                Set<String> vals = Sets.newHashSet(refs);
                location.load = false;

                for (String v : vals) {
                    if (!onProperty.apply(v)) {
                        break;
                    }
                }

                if (vals.contains(uuid)) {
                    return null;
                } else {
                    return vals;
                }

            } else {
                // lazy load, process callback and lookup online
                Set<String> vals = new HashSet<>();
                boolean callback = true;
                for (String v : refs) {
                    if (callback) {
                        callback = onProperty.apply(v);
                    }
                    if (v.equals(uuid)) {
                        return null;
                    }
                    vals.add(v);
                }
                return vals;
            }
        }

        private static Tree getOrAdd(Tree t, String name, String type) {
            Tree c;
            if (t.hasChild(name)) {
                c = t.getChild(name);
            } else {
                c = t.addChild(name);
                c.setProperty(JcrConstants.JCR_PRIMARYTYPE, type, NAME);
            }
            return c;
        }

        private static void setRepMembers(Tree t, Iterable<String> ids) {
            PropertyBuilder<String> propertyBuilder;
            propertyBuilder = PropertyBuilder.array(Type.WEAKREFERENCE, UserConstants.REP_MEMBERS);
            propertyBuilder.addValues(ids);
            t.setProperty(propertyBuilder.getPropertyState());
        }

        private static String idToKey(String id, int level) {
            return id.charAt(level) + "";
        }

        private static boolean isLeafType(Tree t, int level) {
            if (level == -1) {
                return !t.hasChild(UserConstants.REP_MEMBERS_LIST);
            } else {
                String pt = TreeUtil.getName(t, JcrConstants.JCR_PRIMARYTYPE);
                return UserConstants.NT_REP_MEMBER_REFERENCES.equals(pt);
            }
        }

        private static Map<String, Set<String>> groupByKey(Set<String> uuids, int level) {
            Map<String, Set<String>> ret = new HashMap<>();
            for (String uuid : uuids) {
                String key = idToKey(uuid, level);
                Set<String> vals = ret.get(key);
                if (vals == null) {
                    vals = new HashSet<>();
                }
                vals.add(uuid);
                ret.put(key, vals);
            }
            return ret;
        }

        @Override
        public Set<String> removeMembers(@Nonnull Tree groupTree, @Nonnull Map<String, String> memberIds) {
            Set<String> failed = new HashSet<String>(memberIds.size());
            for (Entry<String, String> e : memberIds.entrySet()) {
                if (!removeMember(e.getKey(), groupTree, 0)) {
                    failed.add(e.getValue());
                }
            }
            return failed;
        }

        private static boolean removeMember(String uuid, Tree t, int level) {
            // if property exists, we're sure this is a leaf
            PropertyState refs = t.getProperty(UserConstants.REP_MEMBERS);
            if (refs != null) {
                Set<String> vals = Sets.newHashSet(refs.getValue(Type.WEAKREFERENCES));
                if (vals.remove(uuid)) {
                    if (vals.isEmpty()) {
                        if (level > 0) {
                            // TODO more aggressive pruning in case of deletes
                            t.remove();
                        } else {
                            t.removeProperty(UserConstants.REP_MEMBERS);
                        }
                    } else {
                        PropertyBuilder<String> propertyBuilder = PropertyBuilder.array(Type.WEAKREFERENCE,
                                UserConstants.REP_MEMBERS);
                        propertyBuilder.addValues(vals);
                        t.setProperty(propertyBuilder.getPropertyState());
                    }
                    return true;
                } else {
                    return false;
                }
            } else if (isLeafType(t, level)) {
                return false;
            } else {
                // continue going down the tree
                if (level == 0) {
                    t = t.getChild(UserConstants.REP_MEMBERS_LIST);
                    if (!t.exists()) {
                        return false;
                    }
                }
                String key = idToKey(uuid, level);
                if (t.hasChild(key)) {
                    return removeMember(uuid, t.getChild(key), level + 1);
                } else {
                    return false;
                }
            }
        }
    }

    private static class ListWriter implements WriterStrategy {

        private int membershipSizeThreshold = DEFAULT_MEMBERSHIP_THRESHOLD;

        public void setMembershipSizeThreshold(int membershipSizeThreshold) {
            this.membershipSizeThreshold = membershipSizeThreshold;
        }

        @Override
        public Set<String> addMembers(@Nonnull Tree groupTree, @Nonnull Map<String, String> memberIds)
                throws RepositoryException {

            // check all possible rep:members properties for the new member and also find the one with the least values
            Tree membersList = groupTree.getChild(UserConstants.REP_MEMBERS_LIST);
            Iterator<Tree> trees = Iterators.concat(
                    Iterators.singletonIterator(groupTree),
                    membersList.getChildren().iterator()
            );

            Set<String> failed = new HashSet<String>(memberIds.size());
            int bestCount = membershipSizeThreshold;
            PropertyState bestProperty = null;
            Tree bestTree = null;

            // remove existing memberIds from the map and find best-matching tree
            // for the insertion of the new members.
            while (trees.hasNext() && !memberIds.isEmpty()) {
                Tree t = trees.next();
                PropertyState refs = t.getProperty(UserConstants.REP_MEMBERS);
                if (refs != null) {
                    int numRefs = 0;
                    for (String ref : refs.getValue(Type.WEAKREFERENCES)) {
                        String id = memberIds.remove(ref);
                        if (id != null) {
                            failed.add(id);
                            if (memberIds.isEmpty()) {
                                break;
                            }
                        }
                        numRefs++;
                    }
                    if (numRefs < bestCount) {
                        bestCount = numRefs;
                        bestProperty = refs;
                        bestTree = t;
                    }
                }
            }

            // update member content structure by starting inserting new member IDs
            // with the best-matching property and create new member-ref-nodes as needed.
            if (!memberIds.isEmpty()) {
                PropertyBuilder<String> propertyBuilder;
                int propCnt;
                if (bestProperty == null) {
                    // we don't have a good candidate to store the new members.
                    // so there are no members at all or all are full
                    if (!groupTree.hasProperty(UserConstants.REP_MEMBERS)) {
                        bestTree = groupTree;
                    } else {
                        bestTree = createMemberRefTree(groupTree, membersList);
                    }
                    propertyBuilder = PropertyBuilder.array(Type.WEAKREFERENCE, UserConstants.REP_MEMBERS);
                    propCnt = 0;
                } else {
                    propertyBuilder = PropertyBuilder.copy(Type.WEAKREFERENCE, bestProperty);
                    propCnt = bestCount;
                }
                // if adding all new members to best-property would exceed the threshold
                // the new ids need to be distributed to different member-ref-nodes
                // for simplicity this is achieved by introducing new tree(s)
                if ((propCnt + memberIds.size()) > membershipSizeThreshold) {
                    while (!memberIds.isEmpty()) {
                        Set<String> s = new HashSet<String>();
                        Iterator<String> it = memberIds.keySet().iterator();
                        while (propCnt < membershipSizeThreshold && it.hasNext()) {
                            s.add(it.next());
                            it.remove();
                            propCnt++;
                        }
                        propertyBuilder.addValues(s);
                        bestTree.setProperty(propertyBuilder.getPropertyState());

                        if (it.hasNext()) {
                            // continue filling the next (new) node + propertyBuilder pair
                            propCnt = 0;
                            bestTree = createMemberRefTree(groupTree, membersList);
                            propertyBuilder = PropertyBuilder.array(Type.WEAKREFERENCE, UserConstants.REP_MEMBERS);
                        }
                    }
                } else {
                    propertyBuilder.addValues(memberIds.keySet());
                    bestTree.setProperty(propertyBuilder.getPropertyState());
                }
            }
            return failed;
        }

        private static Tree createMemberRefTree(@Nonnull Tree groupTree, @Nonnull Tree membersList) {
            if (!membersList.exists()) {
                membersList = groupTree.addChild(UserConstants.REP_MEMBERS_LIST);
                membersList.setProperty(JcrConstants.JCR_PRIMARYTYPE, UserConstants.NT_REP_MEMBER_REFERENCES_LIST, NAME);
            }
            Tree refTree = membersList.addChild(nextRefNodeName(membersList));
            refTree.setProperty(JcrConstants.JCR_PRIMARYTYPE, UserConstants.NT_REP_MEMBER_REFERENCES, NAME);
            return refTree;
        }

        private static String nextRefNodeName(@Nonnull Tree membersList) {
            // keep node names linear
            int i = 0;
            String name = String.valueOf(i);
            while (membersList.hasChild(name)) {
                name = String.valueOf(++i);
            }
            return name;
        }

        @Override
        public Set<String> removeMembers(@Nonnull Tree groupTree, @Nonnull Map<String, String> memberIds) {
            Tree membersList = groupTree.getChild(UserConstants.REP_MEMBERS_LIST);
            Iterator<Tree> trees = Iterators.concat(
                    Iterators.singletonIterator(groupTree),
                    membersList.getChildren().iterator()
            );
            while (trees.hasNext() && !memberIds.isEmpty()) {
                Tree t = trees.next();
                PropertyState refs = t.getProperty(UserConstants.REP_MEMBERS);
                if (refs != null) {
                    PropertyBuilder<String> prop = PropertyBuilder.copy(Type.WEAKREFERENCE, refs);
                    Iterator<Map.Entry<String,String>> it = memberIds.entrySet().iterator();
                    while (it.hasNext() && !prop.isEmpty()) {
                        String memberContentId = it.next().getKey();
                        if (prop.hasValue(memberContentId)) {
                            prop.removeValue(memberContentId);
                            it.remove();
                        }
                    }
                    if (prop.isEmpty()) {
                        if (t == groupTree) {
                            t.removeProperty(UserConstants.REP_MEMBERS);
                        } else {
                            t.remove();
                        }
                    } else {
                        t.setProperty(prop.getPropertyState());
                    }
                }
            }
            return Sets.newHashSet(memberIds.values());
        }

    }
}