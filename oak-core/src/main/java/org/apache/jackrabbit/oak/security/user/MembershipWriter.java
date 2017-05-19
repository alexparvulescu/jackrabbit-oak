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
import static com.google.common.collect.Lists.newLinkedList;

import java.util.Collection;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

import javax.annotation.Nonnull;
import javax.jcr.RepositoryException;

import org.apache.jackrabbit.JcrConstants;
import org.apache.jackrabbit.oak.api.PropertyState;
import org.apache.jackrabbit.oak.api.Tree;
import org.apache.jackrabbit.oak.api.Type;
import org.apache.jackrabbit.oak.plugins.memory.PropertyBuilder;
import org.apache.jackrabbit.oak.plugins.tree.TreeUtil;
import org.apache.jackrabbit.oak.spi.security.user.UserConstants;

import com.google.common.collect.Iterators;
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
            Set<String> failed = new HashSet<String>(memberIds.size());
            addMembers(groupTree, -1, membershipSizeThreshold, MAX_LEVEL, memberIds, failed, memberIds.keySet(), false);
            return failed;
        }

        static void addMembers(@Nonnull Tree t, int level, int threshold, int maxLevel,
                @Nonnull Map<String, String> memberIds, @Nonnull Set<String> failed, @Nonnull Collection<String> values,
                boolean force) {

            // if property exists, we're sure this is a leaf
            PropertyState refs = t.getProperty(UserConstants.REP_MEMBERS);
            if (force || refs != null) {
                List<String> newVals = filterAndGet(refs, values, memberIds, failed);
                if (newVals == null) {
                    return;
                }
                newVals.addAll(values);

                if (newVals.size() <= threshold || level >= maxLevel) {
                    setRepMembers(t, newVals);

                } else {
                    // merge & split
                    t.removeProperty(UserConstants.REP_MEMBERS);
                    if (level == -1) {
                        t = t.addChild(UserConstants.REP_MEMBERS_LIST);
                    }
                    // change node type from 'refs' to 'ref list'
                    t.setProperty(JcrConstants.JCR_PRIMARYTYPE, UserConstants.NT_REP_MEMBER_REFERENCES_LIST, NAME);
                    addMembersAsTree(t, level, threshold, maxLevel, memberIds, failed, newVals, true);
                }
            } else if (isLeafType(t, level)) {
                addMembers(t, level, threshold, maxLevel, memberIds, failed, values, true);
            } else {
                // continue going down the tree
                if (level == -1) {
                    t = getOrAdd(t, UserConstants.REP_MEMBERS_LIST, UserConstants.NT_REP_MEMBER_REFERENCES_LIST, false);
                }
                addMembersAsTree(t, level, threshold, maxLevel, memberIds, failed, values, false);
            }
        }

        private static void addMembersAsTree(Tree t, int level, int threshold, int maxLevel,
                Map<String, String> memberIds, Set<String> failed, Collection<String> values, boolean forceAdd) {
            level++;
            Map<String, Collection<String>> groupped = groupByKey(values, level);
            for (Entry<String, Collection<String>> e : groupped.entrySet()) {
                String key = e.getKey();
                Tree c = getOrAdd(t, key, UserConstants.NT_REP_MEMBER_REFERENCES, forceAdd);
                addMembers(c, level, threshold, maxLevel, memberIds, failed, e.getValue(), true);
            }
        }

        private static List<String> filterAndGet(PropertyState refs, Collection<String> values,
                Map<String, String> memberIds, Set<String> failed) {
            if (refs == null) {
                return newLinkedList();
            }
            for (String ref : refs.getValue(Type.WEAKREFERENCES)) {
                if (values.contains(ref)) {
                    failed.add(memberIds.get(ref));
                    values.remove(ref);
                    // check if I can stop the iteration early
                    if (values.isEmpty()) {
                        return null;
                    }
                }
            }
            return newLinkedList(refs.getValue(Type.WEAKREFERENCES));
        }

        private static Tree getOrAdd(Tree t, String name, String type, boolean force) {
            Tree c;
            if (!force && t.hasChild(name)) {
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

        private static Map<String, Collection<String>> groupByKey(Collection<String> uuids, int level) {
            Map<String, Collection<String>> ret = Maps.newHashMapWithExpectedSize(16);
            for (String uuid : uuids) {
                String key = idToKey(uuid, level);
                Collection<String> vals = ret.get(key);
                if (vals == null) {
                    vals =  newLinkedList();
                }
                vals.add(uuid);
                ret.put(key, vals);
            }
            return ret;
        }

        @Override
        public Set<String> removeMembers(@Nonnull Tree groupTree, @Nonnull Map<String, String> memberIds) {
            Set<String> failed = Sets.newHashSet();
            Set<String> rms = Sets.newHashSet(memberIds.keySet());
            removeMembers(groupTree, -1, memberIds, failed, rms);
            return failed;
        }

        private static void removeMembers(Tree t, int level, Map<String, String> memberIds, Set<String> failed, Collection<String> rms) {
            // if property exists, we're sure this is a leaf
            PropertyState refs = t.getProperty(UserConstants.REP_MEMBERS);
            if (refs != null) {
                Set<String> vals = Sets.newHashSet(refs.getValue(Type.WEAKREFERENCES));
                boolean dirty = false;
                Iterator<String> it = vals.iterator();
                while (it.hasNext()) {
                    String v = it.next();
                    if (rms.remove(v)) {
                        it.remove();
                        dirty = true;
                        if (rms.isEmpty()) {
                            break;
                        }
                    }
                }
                for (String k : rms) {
                    failed.add(memberIds.get(k));
                }
                if (dirty) {
                    if (vals.isEmpty()) {
                        if (level < 0) {
                            // TODO remove OR set to empty?
                            t.removeProperty(UserConstants.REP_MEMBERS);
                        } else {
                            // TODO more aggressive pruning in case of deletes
                            t.remove();
                        }
                    } else {
                        setRepMembers(t, vals);
                    }
                }
            } else if (isLeafType(t, level)) {
                for (String k : rms) {
                    failed.add(memberIds.get(k));
                }

            } else {
                // continue going down the tree
                if (level == -1) {
                    t = t.getChild(UserConstants.REP_MEMBERS_LIST);
                    if (!t.exists()) {
                        return;
                    }
                }
                level++;
                Map<String, Collection<String>> groupped = groupByKey(rms, level);
                for (Entry<String, Collection<String>> e : groupped.entrySet()) {
                    String key = e.getKey();
                    if (t.hasChild(key)) {
                        removeMembers(t.getChild(key), level, memberIds, failed, e.getValue());
                    }
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