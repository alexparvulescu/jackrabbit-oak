/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.jackrabbit.oak.security.user;

import com.google.common.collect.Sets;
import org.apache.jackrabbit.oak.api.PropertyState;
import org.apache.jackrabbit.oak.api.Type;
import org.apache.jackrabbit.oak.plugins.memory.PropertyBuilder;
import org.apache.jackrabbit.oak.spi.commit.ThreeWayConflictHandler;
import org.apache.jackrabbit.oak.spi.security.user.UserConstants;
import org.apache.jackrabbit.oak.spi.state.NodeBuilder;
import org.apache.jackrabbit.oak.spi.state.NodeState;

import java.util.Set;

/**
 * The <tt>RepMembersConflictHandler</tt> takes care of merging the <tt>rep:members</tt> property
 * during parallel updates. Change merges are done pessimistically, in that only members of both change sets
 * are included in the result.
 *
 * The conflict handler deals with the following conflicts:
 * <ul>
 *     <li>Ours and theirs add members: The result is a de-duplicated concatenation of the two member-lists</li>
 *     <li>Any other combination of changes: The result is a member-list that contains only those members occurring in
 *     ours as well as theirs.</li>
 * </ul>
 */
public class RepMembersConflictHandler implements ThreeWayConflictHandler {

    @Override
    public Resolution addExistingProperty(NodeBuilder parent, PropertyState ours, PropertyState theirs,
            PropertyState base) {
        if (isRepMembersProperty(theirs)) {
            mergeAdd(parent, ours, theirs);
            return Resolution.MERGED;
        } else {
             return Resolution.IGNORED;
        }
    }

    @Override
    public Resolution changeChangedProperty(NodeBuilder parent, PropertyState ours, PropertyState theirs,
            PropertyState base) {
        if (isRepMembersProperty(theirs)) {
            mergeChange(parent, ours, theirs, base);
            return Resolution.MERGED;
        } else {
             return Resolution.IGNORED;
        }
    }

    @Override
    public Resolution changeDeletedProperty(NodeBuilder parent, PropertyState ours, PropertyState base) {
        if (isRepMembersProperty(ours)) {
            // removing the members property takes precedence
            return Resolution.THEIRS;
        } else {
            return Resolution.IGNORED;
        }
    }

    @Override
    public Resolution deleteChangedProperty(NodeBuilder parent, PropertyState theirs, PropertyState base) {
        if (isRepMembersProperty(theirs)) {
            // removing the members property takes precedence
            return Resolution.OURS;
        } else {
            return Resolution.IGNORED;
        }
    }

    @Override
    public Resolution deleteDeletedProperty(NodeBuilder parent, PropertyState ours, PropertyState base) {
        if (isRepMembersProperty(ours)) {
            // both are removing the members property, resolve
            return Resolution.THEIRS;
        } else {
            return Resolution.IGNORED;
        }
    }

    @Override
    public Resolution addExistingNode(NodeBuilder parent, String name, NodeState ours, NodeState theirs,
            NodeState base) {
        return Resolution.IGNORED;
    }

    @Override
    public Resolution changeDeletedNode(NodeBuilder parent, String name, NodeState ours, NodeState base) {
        return Resolution.IGNORED;
    }

    @Override
    public Resolution deleteChangedNode(NodeBuilder parent, String name, NodeState theirs, NodeState base) {
        return Resolution.IGNORED;
    }

    @Override
    public Resolution deleteDeletedNode(NodeBuilder parent, String name, NodeState base) {
        return Resolution.IGNORED;
    }

    //----------------------------< internal >----------------------------------

    private static void mergeAdd(NodeBuilder parent, PropertyState ours, PropertyState theirs) {
        PropertyBuilder<String> merged = PropertyBuilder.array(Type.STRING);
        merged.setName(UserConstants.REP_MEMBERS);

        Set<String> theirMembers = Sets.newHashSet(theirs.getValue(Type.STRINGS));
        Set<String> ourMembers = Sets.newHashSet(ours.getValue(Type.STRINGS));
        Set<String> combined = Sets.union(theirMembers, ourMembers);

        merged.addValues(combined);
        parent.setProperty(merged.getPropertyState());
    }

    private static void mergeChange(NodeBuilder parent, PropertyState ours, PropertyState theirs, PropertyState base) {
        PropertyBuilder<String> merged = PropertyBuilder.array(Type.STRING);
        merged.setName(UserConstants.REP_MEMBERS);

        Set<String> theirMembers = Sets.newHashSet(theirs.getValue(Type.STRINGS));
        Set<String> ourMembers = Sets.newHashSet(ours.getValue(Type.STRINGS));
        Set<String> baseMembers = Sets.newHashSet(base.getValue(Type.STRINGS));

        // merge ours and theirs to a de-duplicated set
        Set<String> combined = Sets.newHashSet(Sets.intersection(ourMembers, theirMembers));
        for (String m : Sets.difference(ourMembers, theirMembers)) {
            if (!baseMembers.contains(m)) {
                combined.add(m);
            }
        }
        for (String m : Sets.difference(theirMembers, ourMembers)) {
            if (!baseMembers.contains(m)) {
                combined.add(m);
            }
        }
        merged.addValues(combined);
        parent.setProperty(merged.getPropertyState());
    }

    private static boolean isRepMembersProperty(PropertyState p) {
        return UserConstants.REP_MEMBERS.equals(p.getName());
    }

}
