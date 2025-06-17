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
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.rub.nds.protocol.crypto.CyclicGroup;
import de.rub.nds.protocol.crypto.ffdh.FfdhGroup;
import java.math.BigInteger;
import org.junit.jupiter.api.Test;

class FfdhGroupParametersTest {

    // Concrete implementation of the abstract FfdhGroupParameters class for testing
    private static class TestFfdhGroupParameters extends FfdhGroupParameters {
        public TestFfdhGroupParameters(BigInteger generator, BigInteger modulus) {
            super(generator, modulus);
        }
    }

    @Test
    void testConstructorAndGetters() {
        // Create test parameters
        BigInteger generator = BigInteger.valueOf(2);
        BigInteger modulus = BigInteger.valueOf(23); // Small prime for testing

        // Instantiate the test implementation
        FfdhGroupParameters params = new TestFfdhGroupParameters(generator, modulus);

        // Test getters
        assertEquals(generator, params.getGenerator());
        assertEquals(modulus, params.getModulus());
    }

    @Test
    void testGroupParametersImplementation() {
        // Create test parameters
        BigInteger generator = BigInteger.valueOf(2);
        BigInteger modulus = BigInteger.valueOf(23);

        // Instantiate the test implementation
        FfdhGroupParameters params = new TestFfdhGroupParameters(generator, modulus);

        // Test element size methods
        assertEquals(5, params.getElementSizeBits()); // log2(23) ~ 4.52 bits
        assertEquals(1, params.getElementSizeBytes()); // Ceiling of 4.52/8 = 1 byte

        // Test that getGroup returns a FfdhGroup
        CyclicGroup<BigInteger> group = params.getGroup();
        assertNotNull(group);
        assertTrue(group instanceof FfdhGroup);

        // Verify the group has the correct parameters
        FfdhGroup ffdhGroup = (FfdhGroup) group;
        assertEquals(params, ffdhGroup.getParameters());
    }

    @Test
    void testLargeGroupParameters() {
        // Create test parameters with larger values
        BigInteger generator = BigInteger.valueOf(2);
        BigInteger modulus =
                new BigInteger(
                        "115792089237316195423570985008687907853269984665640564039457584007913129639747");

        // Instantiate the test implementation
        FfdhGroupParameters params = new TestFfdhGroupParameters(generator, modulus);

        // Test element size methods
        assertEquals(256, params.getElementSizeBits());
        assertEquals(32, params.getElementSizeBytes());

        // Test that getGroup returns a FfdhGroup
        CyclicGroup<BigInteger> group = params.getGroup();
        assertNotNull(group);
        assertTrue(group instanceof FfdhGroup);
    }
}
