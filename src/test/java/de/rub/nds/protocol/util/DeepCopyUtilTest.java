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
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

public class DeepCopyUtilTest {

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

        public String getName() {
            return name;
        }

        public void setName(String name) {
            this.name = name;
        }

        public int getValue() {
            return value;
        }

        public void setValue(int value) {
            this.value = value;
        }

        public TestObject getNestedObject() {
            return nestedObject;
        }

        public void setNestedObject(TestObject nestedObject) {
            this.nestedObject = nestedObject;
        }
    }

    // Helper class for testing non-serializable objects
    private static class NonSerializableObject {
        private final Object nonSerializableField = new Object();
    }
}
