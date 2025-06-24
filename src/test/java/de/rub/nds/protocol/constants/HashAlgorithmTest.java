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
import static org.junit.jupiter.api.Assertions.assertNull;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

class HashAlgorithmTest {

    @Test
    void testNoneAlgorithm() {
        assertEquals("1.2.840.113549.2.1", HashAlgorithm.NONE.getHashAlgorithmIdentifierOid());
        assertEquals(0, HashAlgorithm.NONE.getBitLength());
        assertEquals(0, HashAlgorithm.NONE.getSecurityStrength());
        assertNull(HashAlgorithm.NONE.getJavaName());
    }

    @Test
    void testSha256Algorithm() {
        assertEquals(
                "2.16.840.1.101.3.4.2.1", HashAlgorithm.SHA256.getHashAlgorithmIdentifierOid());
        assertEquals(256, HashAlgorithm.SHA256.getBitLength());
        assertEquals(128, HashAlgorithm.SHA256.getSecurityStrength());
        assertEquals("SHA256", HashAlgorithm.SHA256.getJavaName());
    }

    @ParameterizedTest
    @EnumSource(HashAlgorithm.class)
    void testAllHashAlgorithms(HashAlgorithm algorithm) {
        // Test that all hash algorithms have valid properties
        assertNotNull(algorithm.getHashAlgorithmIdentifierOid());

        // Special case for NONE
        if (algorithm != HashAlgorithm.NONE) {
            assert (algorithm.getBitLength() > 0);
            assert (algorithm.getSecurityStrength() > 0);
        }
    }

    @Test
    void testGostAlgorithms() {
        // Test GOST hash algorithms
        assertEquals(
                "1.2.643.7.1.1.2.2", HashAlgorithm.GOST_R3411_12.getHashAlgorithmIdentifierOid());
        assertEquals(256, HashAlgorithm.GOST_R3411_12.getBitLength());
        assertEquals(128, HashAlgorithm.GOST_R3411_12.getSecurityStrength());
        assertEquals("GOST341112", HashAlgorithm.GOST_R3411_12.getJavaName());

        assertEquals(
                "1.2.643.2.2.30.0", HashAlgorithm.GOST_R3411_94.getHashAlgorithmIdentifierOid());
        assertEquals(256, HashAlgorithm.GOST_R3411_94.getBitLength());
        assertEquals(128, HashAlgorithm.GOST_R3411_94.getSecurityStrength());
        assertEquals("GOST341194", HashAlgorithm.GOST_R3411_94.getJavaName());
    }
}
