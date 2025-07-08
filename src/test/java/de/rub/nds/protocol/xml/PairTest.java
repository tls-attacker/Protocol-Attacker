/*
 * Protocol-Attacker - A Framework to create Protocol Analysis Tools
 *
 * Copyright 2023-2024 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.protocol.xml;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import org.junit.jupiter.api.Test;

class PairTest {

    @Test
    void testPairConstructorAndGetters() {
        // Arrange
        String leftValue = "left";
        Integer rightValue = 42;

        // Act
        Pair<String, Integer> pair = new Pair<>(leftValue, rightValue);

        // Assert
        assertEquals(leftValue, pair.getLeftElement());
        assertEquals(rightValue, pair.getRightElement());

        // Test the alias methods too
        assertEquals(leftValue, pair.getKey());
        assertEquals(rightValue, pair.getValue());
    }

    @Test
    void testPairSetters() {
        // Arrange
        Pair<String, Integer> pair = new Pair<>("initial", 0);

        // Act
        pair.setLeftElement("updated");
        pair.setRightElement(100);

        // Assert
        assertEquals("updated", pair.getLeftElement());
        assertEquals(100, pair.getRightElement());
    }

    @Test
    void testPairWithNullValues() {
        // Arrange & Act
        Pair<String, Integer> pair = new Pair<>(null, null);

        // Assert
        assertNull(pair.getLeftElement());
        assertNull(pair.getRightElement());
        assertNull(pair.getKey());
        assertNull(pair.getValue());
    }

    @Test
    void testPairWithDifferentTypes() {
        // Arrange
        Boolean leftValue = true;
        Double rightValue = 3.14;

        // Act
        Pair<Boolean, Double> pair = new Pair<>(leftValue, rightValue);

        // Assert
        assertEquals(leftValue, pair.getLeftElement());
        assertEquals(rightValue, pair.getRightElement());
    }

    @Test
    void testPrivateDefaultConstructor()
            throws NoSuchMethodException,
                    IllegalAccessException,
                    InvocationTargetException,
                    InstantiationException {
        // Arrange
        Constructor<Pair> constructor = Pair.class.getDeclaredConstructor();
        constructor.setAccessible(true);

        // Act
        Pair<?, ?> pair = constructor.newInstance();

        // Assert
        assertNotNull(pair);
        assertNull(pair.getLeftElement());
        assertNull(pair.getRightElement());
        assertNull(pair.getKey());
        assertNull(pair.getValue());
    }
}
