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

import de.rub.nds.protocol.constants.FfdhGroupParameters;
import java.math.BigInteger;
import org.junit.jupiter.api.Test;

class Rfc7919GroupsTest {

    @Test
    void testRfc7919Group2048Properties() {
        FfdhGroupParameters group = new Rfc7919Group2048();
        assertEquals(BigInteger.TWO, group.getGenerator());
        assertEquals(2048, group.getElementSizeBits());
        assertEquals(256, group.getElementSizeBytes());
    }

    @Test
    void testRfc7919Group3072Properties() {
        FfdhGroupParameters group = new Rfc7919Group3072();
        assertEquals(BigInteger.TWO, group.getGenerator());
        assertEquals(3072, group.getElementSizeBits());
        assertEquals(384, group.getElementSizeBytes());
    }

    @Test
    void testRfc7919Group4096Properties() {
        FfdhGroupParameters group = new Rfc7919Group4096();
        assertEquals(BigInteger.TWO, group.getGenerator());
        assertEquals(4096, group.getElementSizeBits());
        assertEquals(512, group.getElementSizeBytes());
    }

    @Test
    void testRfc7919Group6144Properties() {
        FfdhGroupParameters group = new Rfc7919Group6144();
        assertEquals(BigInteger.TWO, group.getGenerator());
        assertEquals(6144, group.getElementSizeBits());
        assertEquals(768, group.getElementSizeBytes());
    }

    @Test
    void testRfc7919Group8192Properties() {
        FfdhGroupParameters group = new Rfc7919Group8192();
        assertEquals(BigInteger.TWO, group.getGenerator());
        assertEquals(8192, group.getElementSizeBits());
        assertEquals(1024, group.getElementSizeBytes());
    }

    @Test
    void testRfc7919GroupOperations() {
        // Test that all groups produce valid results for basic group operations
        FfdhGroupParameters[] groups = {
            new Rfc7919Group2048(),
            new Rfc7919Group3072(),
            new Rfc7919Group4096(),
            new Rfc7919Group6144(),
            new Rfc7919Group8192()
        };

        for (FfdhGroupParameters params : groups) {
            FfdhGroup group = new FfdhGroup(params);
            BigInteger g = params.getGenerator();
            BigInteger p = params.getModulus();

            // Test that g^2 mod p is calculated correctly
            BigInteger expectedGSquared = g.modPow(BigInteger.valueOf(2), p);
            assertEquals(
                    expectedGSquared, group.nTimesGroupOperationOnGenerator(BigInteger.valueOf(2)));

            // Test that g^3 mod p is calculated correctly
            BigInteger expectedGCubed = g.modPow(BigInteger.valueOf(3), p);
            assertEquals(
                    expectedGCubed, group.nTimesGroupOperationOnGenerator(BigInteger.valueOf(3)));
        }
    }
}
