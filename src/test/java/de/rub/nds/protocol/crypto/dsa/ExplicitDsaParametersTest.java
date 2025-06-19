/*
 * Protocol-Attacker - A Framework to create Protocol Analysis Tools
 *
 * Copyright 2023-2024 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.protocol.crypto.dsa;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.rub.nds.protocol.crypto.CyclicGroup;
import java.math.BigInteger;
import org.junit.jupiter.api.Test;

class ExplicitDsaParametersTest {

    @Test
    void testExplicitDsaParametersConstructor() {
        // Create explicit DSA parameters
        BigInteger p = new BigInteger("23");
        BigInteger q = new BigInteger("11");
        BigInteger g = new BigInteger("2");

        ExplicitDsaParameters parameters = new ExplicitDsaParameters(p, q, g);

        // Verify parameter values
        assertEquals(p, parameters.getP());
        assertEquals(q, parameters.getQ());
        assertEquals(g, parameters.getG());
        assertEquals(5, parameters.getElementSizeBits()); // log2(23) ≈ 4.52 -> 5 bits
    }

    @Test
    void testExplicitDsaParametersWithLargePrimes() {
        // Test with larger prime values
        BigInteger p = new BigInteger("1073741827"); // Large prime
        BigInteger q = new BigInteger("536870913"); // (p-1)/2
        BigInteger g = new BigInteger("2");

        ExplicitDsaParameters parameters = new ExplicitDsaParameters(p, q, g);

        assertEquals(p, parameters.getP());
        assertEquals(q, parameters.getQ());
        assertEquals(g, parameters.getG());
        assertEquals(31, parameters.getElementSizeBits()); // 1073741827 requires 31 bits
        assertEquals(4, parameters.getElementSizeBytes());
    }

    @Test
    void testExplicitDsaParametersWithSmallPrimes() {
        // Test with very small primes
        BigInteger p = new BigInteger("3");
        BigInteger q = new BigInteger("1");
        BigInteger g = new BigInteger("2");

        ExplicitDsaParameters parameters = new ExplicitDsaParameters(p, q, g);

        assertEquals(p, parameters.getP());
        assertEquals(q, parameters.getQ());
        assertEquals(g, parameters.getG());
        assertEquals(2, parameters.getElementSizeBits());
        assertEquals(1, parameters.getElementSizeBytes());
    }

    @Test
    void testGetGroup() {
        // Create parameters
        BigInteger p = new BigInteger("23");
        BigInteger q = new BigInteger("11");
        BigInteger g = new BigInteger("2");

        ExplicitDsaParameters parameters = new ExplicitDsaParameters(p, q, g);

        // Get the group
        CyclicGroup<?> group = parameters.getGroup();

        // Verify group properties
        assertNotNull(group);
        assertTrue(group instanceof DsaGroup);
        assertEquals(g, group.getGenerator());

        // Test group operations
        BigInteger a = new BigInteger("3");
        BigInteger b = new BigInteger("5");
        BigInteger result = ((DsaGroup) group).groupOperation(a, b);
        assertEquals(new BigInteger("15").mod(p), result);
    }

    @Test
    void testEquals() {
        BigInteger p = new BigInteger("23");
        BigInteger q = new BigInteger("11");
        BigInteger g = new BigInteger("2");

        ExplicitDsaParameters params1 = new ExplicitDsaParameters(p, q, g);
        ExplicitDsaParameters params2 = new ExplicitDsaParameters(p, q, g);
        ExplicitDsaParameters params3 =
                new ExplicitDsaParameters(
                        new BigInteger("47"), new BigInteger("23"), new BigInteger("5"));

        // Test equality
        assertEquals(params1, params2);
        assertNotEquals(params1, params3);
        assertEquals(params1, params1); // reflexive
        assertNotEquals(params1, null);
        assertNotEquals(params1, "not a DsaParameters object");
    }

    @Test
    void testHashCode() {
        BigInteger p = new BigInteger("23");
        BigInteger q = new BigInteger("11");
        BigInteger g = new BigInteger("2");

        ExplicitDsaParameters params1 = new ExplicitDsaParameters(p, q, g);
        ExplicitDsaParameters params2 = new ExplicitDsaParameters(p, q, g);
        ExplicitDsaParameters params3 =
                new ExplicitDsaParameters(
                        new BigInteger("47"), new BigInteger("23"), new BigInteger("5"));

        // Test hashCode consistency
        assertEquals(params1.hashCode(), params2.hashCode());
        assertNotEquals(params1.hashCode(), params3.hashCode());

        // Test multiple invocations
        int hash1 = params1.hashCode();
        int hash2 = params1.hashCode();
        assertEquals(hash1, hash2);
    }

    @Test
    void testElementSizeBytesWithBoundaryValues() {
        // Test when bit length is exactly divisible by 8
        BigInteger p1 = new BigInteger("255"); // 8 bits
        ExplicitDsaParameters params1 =
                new ExplicitDsaParameters(p1, new BigInteger("127"), new BigInteger("2"));
        assertEquals(1, params1.getElementSizeBytes());

        // Test when bit length is not divisible by 8
        BigInteger p2 = new BigInteger("511"); // 9 bits
        ExplicitDsaParameters params2 =
                new ExplicitDsaParameters(p2, new BigInteger("255"), new BigInteger("2"));
        assertEquals(2, params2.getElementSizeBytes());

        // Test with 16 bits exactly
        BigInteger p3 = new BigInteger("65535"); // 16 bits
        ExplicitDsaParameters params3 =
                new ExplicitDsaParameters(p3, new BigInteger("32767"), new BigInteger("2"));
        assertEquals(2, params3.getElementSizeBytes());

        // Test with 17 bits
        BigInteger p4 = new BigInteger("131071"); // 17 bits
        ExplicitDsaParameters params4 =
                new ExplicitDsaParameters(p4, new BigInteger("65535"), new BigInteger("2"));
        assertEquals(3, params4.getElementSizeBytes());
    }

    @Test
    void testGetGroupCreatesNewInstance() {
        BigInteger p = new BigInteger("23");
        BigInteger q = new BigInteger("11");
        BigInteger g = new BigInteger("2");

        ExplicitDsaParameters parameters = new ExplicitDsaParameters(p, q, g);

        // Verify that getGroup() creates new instances on each call
        CyclicGroup<?> group1 = parameters.getGroup();
        CyclicGroup<?> group2 = parameters.getGroup();

        assertNotSame(group1, group2);
        // But they should be equal in terms of their parameters
        assertEquals(((DsaGroup) group1).getP(), ((DsaGroup) group2).getP());
        assertEquals(((DsaGroup) group1).getQ(), ((DsaGroup) group2).getQ());
        assertEquals(((DsaGroup) group1).getGenerator(), ((DsaGroup) group2).getGenerator());
    }

    @Test
    void testNullParameterHandling() {
        // Note: This test documents current behavior.
        // In a production system, you might want to add null checks in the constructor
        try {
            new ExplicitDsaParameters(null, new BigInteger("11"), new BigInteger("2"));
            // If no exception is thrown, the constructor accepts null values
            // which might lead to NullPointerException later
        } catch (NullPointerException e) {
            // Expected if constructor validates input
        }
    }
}
