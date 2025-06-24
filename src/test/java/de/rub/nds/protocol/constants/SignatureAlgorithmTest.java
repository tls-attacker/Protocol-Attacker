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

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

class SignatureAlgorithmTest {

    @ParameterizedTest
    @CsvSource({
        "RSA_PKCS1, RSA PKCS#1.5",
        "DSA, DSA (DSS)",
        "ECDSA, ECDSA",
        "RSA_SSA_PSS, RSASSA PSS",
        "ED25519, Ed25519",
        "ED448, Ed448",
        "GOSTR34102001, GOSTR34102001",
        "GOSTR34102012_256, GOSTR34102012 (256 bit)",
        "GOSTR34102012_512, GOSTR34102012 (512 bit)"
    })
    void testSignatureAlgorithmHumanReadable(String algorithmName, String expectedHumanReadable) {
        SignatureAlgorithm algorithm = SignatureAlgorithm.valueOf(algorithmName);
        assertEquals(expectedHumanReadable, algorithm.getHumanReadable());
    }

    @Test
    void testAllAlgorithmsHaveHumanReadableValue() {
        for (SignatureAlgorithm algorithm : SignatureAlgorithm.values()) {
            assertNotNull(algorithm.getHumanReadable());
        }
    }

    @Test
    void testEnumValues() {
        // Test the number of defined signature algorithms
        assertEquals(9, SignatureAlgorithm.values().length);

        // Test specific algorithm values
        assertEquals(SignatureAlgorithm.RSA_PKCS1, SignatureAlgorithm.valueOf("RSA_PKCS1"));
        assertEquals(SignatureAlgorithm.DSA, SignatureAlgorithm.valueOf("DSA"));
        assertEquals(SignatureAlgorithm.ECDSA, SignatureAlgorithm.valueOf("ECDSA"));
        assertEquals(SignatureAlgorithm.RSA_SSA_PSS, SignatureAlgorithm.valueOf("RSA_SSA_PSS"));
        assertEquals(SignatureAlgorithm.ED25519, SignatureAlgorithm.valueOf("ED25519"));
        assertEquals(SignatureAlgorithm.ED448, SignatureAlgorithm.valueOf("ED448"));
        assertEquals(SignatureAlgorithm.GOSTR34102001, SignatureAlgorithm.valueOf("GOSTR34102001"));
        assertEquals(
                SignatureAlgorithm.GOSTR34102012_256,
                SignatureAlgorithm.valueOf("GOSTR34102012_256"));
        assertEquals(
                SignatureAlgorithm.GOSTR34102012_512,
                SignatureAlgorithm.valueOf("GOSTR34102012_512"));
    }
}
