package org.apache.jackrabbit.oak.spi.nodetype.predicates;

import java.util.function.Predicate;

import javax.annotation.Nonnull;

import org.apache.jackrabbit.oak.spi.state.NodeState;

public class TypePredicates {

    private TypePredicates() {
    }

    public static Predicate<NodeState> getNodeTypePredicate(@Nonnull NodeState root, @Nonnull String... names) {
        return new TypePredicate(root, names);
    }

    public static Predicate<NodeState> getNodeTypePredicate(@Nonnull NodeState root, @Nonnull Iterable<String> names) {
        return new TypePredicate(root, names);
    }

}
