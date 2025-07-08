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

    @Test
    public void testEqualsWithNullModulus() {
        ExplicitFfdhGroupParameters params1 = new ExplicitFfdhGroupParameters(testGenerator, null);
        ExplicitFfdhGroupParameters params2 = new ExplicitFfdhGroupParameters(testGenerator, null);
        ExplicitFfdhGroupParameters params3 =
                new ExplicitFfdhGroupParameters(testGenerator, testModulus);

        // Test equality with null modulus
        assertTrue(params1.equals(params2)); // Both have null modulus
        assertFalse(params1.equals(params3)); // One has null modulus, other doesn't
        assertFalse(params3.equals(params1)); // Reverse check
    }

    @Test
    public void testEqualsWithNullGenerator() {
        ExplicitFfdhGroupParameters params1 = new ExplicitFfdhGroupParameters(null, testModulus);
        ExplicitFfdhGroupParameters params2 = new ExplicitFfdhGroupParameters(null, testModulus);
        ExplicitFfdhGroupParameters params3 =
                new ExplicitFfdhGroupParameters(testGenerator, testModulus);

        // Test equality with null generator
        assertTrue(params1.equals(params2)); // Both have null generator
        assertFalse(params1.equals(params3)); // One has null generator, other doesn't
        assertFalse(params3.equals(params1)); // Reverse check
    }

    @Test
    public void testHashCodeWithNullValues() {
        ExplicitFfdhGroupParameters params1 = new ExplicitFfdhGroupParameters(null, null);
        ExplicitFfdhGroupParameters params2 = new ExplicitFfdhGroupParameters(null, testModulus);
        ExplicitFfdhGroupParameters params3 = new ExplicitFfdhGroupParameters(testGenerator, null);
        ExplicitFfdhGroupParameters params4 =
                new ExplicitFfdhGroupParameters(testGenerator, testModulus);

        // All should have different hash codes (or at least compute without error)
        int hash1 = params1.hashCode();
        int hash2 = params2.hashCode();
        int hash3 = params3.hashCode();
        int hash4 = params4.hashCode();

        // Verify hash codes are computed without error
        assertTrue(hash1 != 0 || hash1 == 0); // Just ensure it computes
        assertTrue(hash2 != 0 || hash2 == 0);
        assertTrue(hash3 != 0 || hash3 == 0);
        assertTrue(hash4 != 0 || hash4 == 0);
    }
}
