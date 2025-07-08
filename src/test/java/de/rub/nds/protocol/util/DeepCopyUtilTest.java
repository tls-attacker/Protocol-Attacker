/*
 * Protocol-Attacker - A Framework to create Protocol Analysis Tools
 *
 * Copyright 2023-2024 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.protocol.util;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.Serializable;
import java.lang.reflect.Constructor;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class DeepCopyUtilTest {

    @Test
    void testDeepCopyWithPrimitiveArray() {
        // Arrange
        byte[] original = new byte[] {1, 2, 3, 4, 5};

        // Act
        byte[] copy = DeepCopyUtil.deepCopy(original);

        // Assert
        assertNotSame(original, copy);
        assertEquals(Arrays.toString(original), Arrays.toString(copy));

        // Modify copy and verify original is unchanged
        copy[0] = 99;
        assertEquals(1, original[0]);
        assertEquals(99, copy[0]);
    }

    @Test
    void testDeepCopyWithList() {
        // Arrange
        List<String> original = new ArrayList<>();
        original.add("first");
        original.add("second");

        // Act
        List<String> copy = DeepCopyUtil.deepCopy(original);

        // Assert
        assertNotSame(original, copy);
        assertEquals(original, copy);

        // Modify copy and verify original is unchanged
        copy.add("third");
        assertEquals(2, original.size());
        assertEquals(3, copy.size());
    }

    @Test
    void testDeepCopyWithMap() {
        // Arrange
        Map<String, Integer> original = new HashMap<>();
        original.put("one", 1);
        original.put("two", 2);

        // Act
        Map<String, Integer> copy = DeepCopyUtil.deepCopy(original);

        // Assert
        assertNotSame(original, copy);
        assertEquals(original, copy);

        // Modify copy and verify original is unchanged
        copy.put("three", 3);
        assertEquals(2, original.size());
        assertEquals(3, copy.size());
    }

    @Test
    void testDeepCopyWithNestedObjects() {
        // Arrange
        TestObject innerObj = new TestObject("inner", 10);
        TestObject original = new TestObject("outer", 20);
        original.setNestedObject(innerObj);

        // Act
        TestObject copy = DeepCopyUtil.deepCopy(original);

        // Assert
        assertNotSame(original, copy);
        assertNotSame(original.getNestedObject(), copy.getNestedObject());
        assertEquals(original.getName(), copy.getName());
        assertEquals(original.getValue(), copy.getValue());
        assertEquals(original.getNestedObject().getName(), copy.getNestedObject().getName());

        // Modify copy and verify original is unchanged
        copy.setName("modified");
        copy.getNestedObject().setName("modified-inner");
        assertEquals("outer", original.getName());
        assertEquals("inner", original.getNestedObject().getName());
    }

    @Test
    void testDeepCopyWithNonSerializableObject() {
        // Arrange
        NonSerializableObject original = new NonSerializableObject();

        // Act & Assert
        assertThrows(RuntimeException.class, () -> DeepCopyUtil.deepCopy(original));
    }

    // Helper class for testing deep copy with nested objects
    private static class TestObject implements Serializable {
        private static final long serialVersionUID = 1L;

        private String name;
        private int value;
        private TestObject nestedObject;

        public TestObject(String name, int value) {
            this.name = name;
            this.value = value;
        }

        String getName() {
            return name;
        }

        void setName(String name) {
            this.name = name;
        }

        int getValue() {
            return value;
        }

        void setValue(int value) {
            this.value = value;
        }

        TestObject getNestedObject() {
            return nestedObject;
        }

        void setNestedObject(TestObject nestedObject) {
            this.nestedObject = nestedObject;
        }
    }

    // Helper class for testing non-serializable objects
    private static class NonSerializableObject {
        private final Object nonSerializableField = new Object();
    }

    @Test
    void testPrivateConstructor() throws Exception {
        // Test that the private constructor can be invoked (for coverage)
        Constructor<DeepCopyUtil> constructor = DeepCopyUtil.class.getDeclaredConstructor();
        constructor.setAccessible(true);
        DeepCopyUtil instance = constructor.newInstance();
        assertNotNull(instance);
    }

    @Test
    void testDeepCopyWithNull() {
        // Test deep copy with null value
        String nullValue = null;
        String copiedNull = DeepCopyUtil.deepCopy(nullValue);
        assertEquals(nullValue, copiedNull);
    }

    @Test
    void testDeepCopyWithString() {
        // Test deep copy with String (immutable object)
        String original = "test string";
        String copy = DeepCopyUtil.deepCopy(original);
        assertEquals(original, copy);
        // Strings are immutable, so they might be the same instance
    }

    @Test
    void testDeepCopyWithInteger() {
        // Test deep copy with Integer
        Integer original = 42;
        Integer copy = DeepCopyUtil.deepCopy(original);
        assertEquals(original, copy);
    }

    @Test
    void testDeepCopyWithComplexNestedStructure() {
        // Create a more complex nested structure
        Map<String, List<TestObject>> original = new HashMap<>();

        List<TestObject> list1 = new ArrayList<>();
        TestObject obj1 = new TestObject("obj1", 10);
        TestObject obj2 = new TestObject("obj2", 20);
        obj1.setNestedObject(obj2);
        list1.add(obj1);
        list1.add(obj2);

        original.put("list1", list1);

        // Deep copy
        Map<String, List<TestObject>> copy = DeepCopyUtil.deepCopy(original);

        // Verify the structure is copied correctly
        assertNotSame(original, copy);
        assertNotSame(original.get("list1"), copy.get("list1"));
        assertNotSame(original.get("list1").get(0), copy.get("list1").get(0));
        assertNotSame(original.get("list1").get(1), copy.get("list1").get(1));

        // Verify values are preserved
        assertEquals(original.get("list1").size(), copy.get("list1").size());
        assertEquals(original.get("list1").get(0).getName(), copy.get("list1").get(0).getName());
        assertEquals(original.get("list1").get(0).getValue(), copy.get("list1").get(0).getValue());
    }

    @Test
    void testDeepCopyWithCircularReference() {
        // Test with objects that have circular references
        TestObject obj1 = new TestObject("circular1", 100);
        TestObject obj2 = new TestObject("circular2", 200);
        obj1.setNestedObject(obj2);
        obj2.setNestedObject(obj1); // Circular reference

        // Deep copy should handle circular references
        TestObject copy = DeepCopyUtil.deepCopy(obj1);

        assertNotSame(obj1, copy);
        assertNotSame(obj1.getNestedObject(), copy.getNestedObject());
        assertEquals(obj1.getName(), copy.getName());
        assertEquals(obj1.getNestedObject().getName(), copy.getNestedObject().getName());

        // Verify circular reference is maintained
        assertNotNull(copy.getNestedObject().getNestedObject());
        assertEquals(copy.getName(), copy.getNestedObject().getNestedObject().getName());
    }
}
