/*
 * Protocol-Attacker - A Framework to create Protocol Analysis Tools
 *
 * Copyright 2023-2024 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.protocol.crypto.ffdh;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.rub.nds.protocol.crypto.CyclicGroup;
import java.math.BigInteger;
import org.junit.jupiter.api.Test;

class ExplicitFfdhGroupParametersTest {

    private final BigInteger testGenerator = BigInteger.valueOf(2);
    private final BigInteger testModulus = new BigInteger("FFFFFFFFFFFFFFFFADF85458A2BB4A9A", 16);

    @Test
    void testConstructor() {
        ExplicitFfdhGroupParameters params =
                new ExplicitFfdhGroupParameters(testGenerator, testModulus);
        assertEquals(testGenerator, params.getGenerator());
        assertEquals(testModulus, params.getModulus());
    }

    @Test
    void testGetElementSizeBits() {
        ExplicitFfdhGroupParameters params =
                new ExplicitFfdhGroupParameters(testGenerator, testModulus);
        assertEquals(testModulus.bitLength(), params.getElementSizeBits());
    }

    @Test
    void testGetElementSizeBytes() {
        ExplicitFfdhGroupParameters params =
                new ExplicitFfdhGroupParameters(testGenerator, testModulus);
        int expectedBytes = (int) Math.ceil(((double) testModulus.bitLength()) / 8);
        assertEquals(expectedBytes, params.getElementSizeBytes());
    }

    @Test
    void testGetGroup() {
        ExplicitFfdhGroupParameters params =
                new ExplicitFfdhGroupParameters(testGenerator, testModulus);
        CyclicGroup<BigInteger> group = params.getGroup();
        assertTrue(group instanceof FfdhGroup);
        assertEquals(testGenerator, group.getGenerator());
        assertEquals(testModulus, ((FfdhGroup) group).getModulus());
    }

    @Test
    void testEqualsAndHashCode() {
        ExplicitFfdhGroupParameters params1 =
                new ExplicitFfdhGroupParameters(testGenerator, testModulus);
        ExplicitFfdhGroupParameters params2 =
                new ExplicitFfdhGroupParameters(testGenerator, testModulus);
        ExplicitFfdhGroupParameters params3 =
                new ExplicitFfdhGroupParameters(BigInteger.valueOf(3), testModulus);
        ExplicitFfdhGroupParameters params4 =
                new ExplicitFfdhGroupParameters(testGenerator, testModulus.add(BigInteger.ONE));

        // Test equality
        assertTrue(params1.equals(params1)); // Reflexive
        assertTrue(params1.equals(params2)); // Same values
        assertTrue(params2.equals(params1)); // Symmetric
        assertFalse(params1.equals(params3)); // Different generator
        assertFalse(params1.equals(params4)); // Different modulus
        assertFalse(params1.equals(null)); // Null check
        assertFalse(params1.equals("not a group params")); // Type check

        // Test hash code
        assertEquals(params1.hashCode(), params2.hashCode()); // Same values should have same hash
        assertNotEquals(
                params1.hashCode(),
                params3.hashCode()); // Different values should have different hash
        assertNotEquals(
                params1.hashCode(),
                params4.hashCode()); // Different values should have different hash
    }
}
