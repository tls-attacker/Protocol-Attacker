/*
 * Protocol-Attacker - A Framework to create Protocol Analysis Tools
 *
 * Copyright 2023-2024 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.protocol.crypto.signature;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.util.Modifiable;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class SignatureComputationsTest {

    private TestSignatureComputations computations;
    private byte[] testData = "test signature data".getBytes();

    @BeforeEach
    void setUp() {
        computations = new TestSignatureComputations();
    }

    @Test
    void testSignatureValidGetterSetter() {
        // Initially null
        assertNull(computations.getSignatureValid());

        // Set and get
        computations.setSignatureValid(true);
        assertTrue(computations.getSignatureValid());
    }

    @Test
    void testSignatureBytesGetterSetter() {
        // Initially null
        assertNull(computations.getSignatureBytes());

        // Set and get with ModifiableByteArray
        ModifiableByteArray modifiableBytes = Modifiable.explicit(testData);
        computations.setSignatureBytes(modifiableBytes);
        assertEquals(modifiableBytes, computations.getSignatureBytes());

        // Set and get with byte[]
        computations.setSignatureBytes(testData);
        assertNotNull(computations.getSignatureBytes());
        assertNotNull(computations.getSignatureBytes().getValue());
        assertEquals(testData.length, computations.getSignatureBytes().getValue().length);
    }

    @Test
    void testToBeSignedBytesGetterSetter() {
        // Initially null
        assertNull(computations.getToBeSignedBytes());

        // Set and get with ModifiableByteArray
        ModifiableByteArray modifiableBytes = Modifiable.explicit(testData);
        computations.setToBeSignedBytes(modifiableBytes);
        assertEquals(modifiableBytes, computations.getToBeSignedBytes());

        // Set and get with byte[]
        computations.setToBeSignedBytes(testData);
        assertNotNull(computations.getToBeSignedBytes());
        assertNotNull(computations.getToBeSignedBytes().getValue());
        assertEquals(testData.length, computations.getToBeSignedBytes().getValue().length);
    }

    @Test
    void testDigestBytesGetterSetter() {
        // Initially null
        assertNull(computations.getDigestBytes());

        // Set and get with ModifiableByteArray
        ModifiableByteArray modifiableBytes = Modifiable.explicit(testData);
        computations.setDigestBytes(modifiableBytes);
        assertEquals(modifiableBytes, computations.getDigestBytes());

        // Set and get with byte[]
        computations.setDigestBytes(testData);
        assertNotNull(computations.getDigestBytes());
        assertNotNull(computations.getDigestBytes().getValue());
        assertEquals(testData.length, computations.getDigestBytes().getValue().length);
    }

    // Concrete implementation for testing the abstract class
    private static class TestSignatureComputations extends SignatureComputations {
        // This class is just for testing the abstract SignatureComputations class
    }
}
