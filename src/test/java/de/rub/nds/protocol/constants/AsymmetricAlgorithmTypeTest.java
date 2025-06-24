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

class AsymmetricAlgorithmTypeTest {

    @Test
    void testEnumValues() {
        // Test the number of defined algorithms
        assertEquals(6, AsymmetricAlgorithmType.values().length);

        // Test existence of each algorithm type
        assertEquals(AsymmetricAlgorithmType.RSA, AsymmetricAlgorithmType.valueOf("RSA"));
        assertEquals(AsymmetricAlgorithmType.ECDSA, AsymmetricAlgorithmType.valueOf("ECDSA"));
        assertEquals(AsymmetricAlgorithmType.EDDSA, AsymmetricAlgorithmType.valueOf("EDDSA"));
        assertEquals(AsymmetricAlgorithmType.DSA, AsymmetricAlgorithmType.valueOf("DSA"));
        assertEquals(AsymmetricAlgorithmType.DH, AsymmetricAlgorithmType.valueOf("DH"));
        assertEquals(AsymmetricAlgorithmType.ECDH, AsymmetricAlgorithmType.valueOf("ECDH"));
    }

    @Test
    void testEnumNamesAndToString() {
        // Test that each enum has valid name and toString
        for (AsymmetricAlgorithmType type : AsymmetricAlgorithmType.values()) {
            assertNotNull(type.name());
            assertNotNull(type.toString());
        }
    }

    @Test
    void testEnumOrdinals() {
        // Test that ordinals start at 0 and increment by 1
        assertEquals(0, AsymmetricAlgorithmType.RSA.ordinal());
        assertEquals(1, AsymmetricAlgorithmType.ECDSA.ordinal());
        assertEquals(2, AsymmetricAlgorithmType.EDDSA.ordinal());
        assertEquals(3, AsymmetricAlgorithmType.DSA.ordinal());
        assertEquals(4, AsymmetricAlgorithmType.DH.ordinal());
        assertEquals(5, AsymmetricAlgorithmType.ECDH.ordinal());
    }
}
