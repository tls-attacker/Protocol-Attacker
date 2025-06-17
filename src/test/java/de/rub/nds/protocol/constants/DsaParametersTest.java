/*
 * Protocol-Attacker - A Framework to create Protocol Analysis Tools
 *
 * Copyright 2023-2024 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.protocol.constants;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.rub.nds.protocol.crypto.CyclicGroup;
import de.rub.nds.protocol.crypto.dsa.DsaGroup;
import java.math.BigInteger;
import org.junit.jupiter.api.Test;

class DsaParametersTest {

    // Concrete implementation of the abstract DsaParameters class for testing
    private static class TestDsaParameters extends DsaParameters {
        public TestDsaParameters(BigInteger p, BigInteger q, BigInteger g) {
            super(p, q, g);
        }
    }

    @Test
    void testConstructorAndGetters() {
        // Create test parameters
        BigInteger p = BigInteger.valueOf(23); // Small prime for testing
        BigInteger q = BigInteger.valueOf(11); // Divisor of p-1
        BigInteger g = BigInteger.valueOf(2); // Generator

        // Instantiate the test implementation
        DsaParameters params = new TestDsaParameters(p, q, g);

        // Test getters
        assertEquals(p, params.getP());
        assertEquals(q, params.getQ());
        assertEquals(g, params.getG());
    }

    @Test
    void testGroupParametersImplementation() {
        // Create test parameters
        BigInteger p = BigInteger.valueOf(23);
        BigInteger q = BigInteger.valueOf(11);
        BigInteger g = BigInteger.valueOf(2);

        // Instantiate the test implementation
        DsaParameters params = new TestDsaParameters(p, q, g);

        // Test element size methods
        assertEquals(5, params.getElementSizeBits()); // log2(23) ~ 4.52 bits
        assertEquals(1, params.getElementSizeBytes()); // Ceiling of 4.52/8 = 1 byte

        // Test that getGroup returns a DsaGroup
        CyclicGroup<BigInteger> group = params.getGroup();
        assertNotNull(group);
        assertTrue(group instanceof DsaGroup);

        // Verify the group has the correct parameters
        DsaGroup dsaGroup = (DsaGroup) group;
        assertEquals(params, dsaGroup.getParameters());
    }

    @Test
    void testEqualsAndHashCode() {
        // Create identical parameters
        BigInteger p1 = BigInteger.valueOf(23);
        BigInteger q1 = BigInteger.valueOf(11);
        BigInteger g1 = BigInteger.valueOf(2);
        DsaParameters params1 = new TestDsaParameters(p1, q1, g1);

        // Create identical parameters but different instance
        BigInteger p2 = BigInteger.valueOf(23);
        BigInteger q2 = BigInteger.valueOf(11);
        BigInteger g2 = BigInteger.valueOf(2);
        DsaParameters params2 = new TestDsaParameters(p2, q2, g2);

        // Create different parameters
        BigInteger p3 = BigInteger.valueOf(47);
        BigInteger q3 = BigInteger.valueOf(23);
        BigInteger g3 = BigInteger.valueOf(2);
        DsaParameters params3 = new TestDsaParameters(p3, q3, g3);

        // Test equals method
        assertTrue(params1.equals(params1)); // Same instance
        assertTrue(params1.equals(params2)); // Equal parameters
        assertFalse(params1.equals(params3)); // Different parameters
        assertFalse(params1.equals(null)); // Null check
        assertFalse(params1.equals("Not a DsaParameters")); // Type check

        // Test hashCode method
        assertEquals(params1.hashCode(), params2.hashCode()); // Equal objects have equal hash codes
        assertNotEquals(
                params1.hashCode(),
                params3.hashCode()); // Different objects may have different hash codes
    }
}
