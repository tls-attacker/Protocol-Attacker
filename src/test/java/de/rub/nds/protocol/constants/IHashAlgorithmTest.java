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

import de.rub.nds.protocol.crypto.hash.HashCalculator;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

class IHashAlgorithmTest {

    private static final byte[] TEST_DATA = "Test hash data".getBytes(StandardCharsets.UTF_8);

    // Create a simple implementation of IHashAlgorithm for testing
    private static class TestHashAlgorithm implements IHashAlgorithm {
        private final int bitLength;
        private final int securityStrength;
        private final HashAlgorithm delegateAlgorithm;

        public TestHashAlgorithm(
                int bitLength, int securityStrength, HashAlgorithm delegateAlgorithm) {
            this.bitLength = bitLength;
            this.securityStrength = securityStrength;
            this.delegateAlgorithm = delegateAlgorithm;
        }

        @Override
        public int getBitLength() {
            return bitLength;
        }

        @Override
        public int getSecurityStrength() {
            return securityStrength;
        }

        @Override
        public byte[] computeHash(byte[] data) {
            return HashCalculator.compute(data, delegateAlgorithm);
        }
    }

    @Test
    void testInterfaceMethods() {
        // Create a test implementation of IHashAlgorithm
        IHashAlgorithm hashAlgorithm = new TestHashAlgorithm(256, 128, HashAlgorithm.SHA256);

        // Test getBitLength
        assertEquals(256, hashAlgorithm.getBitLength());

        // Test getSecurityStrength
        assertEquals(128, hashAlgorithm.getSecurityStrength());

        // Test computeHash
        byte[] hash = hashAlgorithm.computeHash(TEST_DATA);
        assertNotNull(hash);
        assertEquals(32, hash.length); // SHA-256 produces 32 bytes
    }

    // This test is commented out because in the current implementation
    // HashAlgorithm doesn't implement IHashAlgorithm yet
    /*
    @Test
    void testHashAlgorithmImplementsIHashAlgorithm() {
        // Verify that HashAlgorithm implements IHashAlgorithm
        HashAlgorithm algorithm = HashAlgorithm.SHA256;
        assertTrue(algorithm instanceof IHashAlgorithm);

        // Test interface methods on HashAlgorithm
        assertEquals(256, algorithm.getBitLength());
        assertEquals(128, algorithm.getSecurityStrength());

        // This will fail if HashAlgorithm doesn't implement computeHash from IHashAlgorithm
        // but it should be implemented in a future version
        // byte[] hash = algorithm.computeHash(TEST_DATA);
        // assertNotNull(hash);
    }
    */
}
