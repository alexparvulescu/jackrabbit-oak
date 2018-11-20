package org.apache.jackrabbit.oak.commons.guava;

import java.lang.reflect.Method;

import org.jetbrains.annotations.Nullable;

public class MoreObjectsCompat {

    public static MoreObjectsCompat toStringHelper(Object self) {
        return toStringHelper(self.getClass().getSimpleName());
    }

    public static MoreObjectsCompat toStringHelper(String className) {
        return new MoreObjectsCompat(className);
    }

    private static final String className = "com.google.common.base.MoreObjects";
    private static final String classNameFallback = "com.google.common.base.Objects";

    private static Object init(String name) {
        ClassLoader classLoader = Thread.currentThread().getContextClassLoader();
        Class<?> clazz;
        try {
            clazz = Class.forName(className, false, classLoader);
        } catch (ClassNotFoundException e) {
            try {
                clazz = Class.forName(classNameFallback, false, classLoader);
            } catch (ClassNotFoundException e1) {
                throw new IllegalStateException("Unable to load '" + className + "' class.", e);
            }
        }
        Method m;
        try {
            m = clazz.getDeclaredMethod("toStringHelper", String.class);
        } catch (Exception e) {
            throw new IllegalStateException("Unable to identify 'toStringHelper' method.", e);
        }

        Object o;
        try {
            o = m.invoke(null, name);
        } catch (Exception e) {
            throw new IllegalStateException("Unable to invoke 'toStringHelper' method.", e);
        }
        return o;
    }

    private final Object helper;

    private MoreObjectsCompat(String name) {
        helper = init(name);
    }

    public MoreObjectsCompat add(String name, long value) {
        return this;
    }

    public MoreObjectsCompat add(String name, @Nullable Object value) {
        return this;
    }

    public MoreObjectsCompat add(String name, int value) {
        return this;
    }

    public MoreObjectsCompat add(String name, boolean value) {
        return this;
    }

    public MoreObjectsCompat addValue(@Nullable Object value) {
        return this;
    }

    @Override
    public String toString() {
        return helper.toString();
    }
}
