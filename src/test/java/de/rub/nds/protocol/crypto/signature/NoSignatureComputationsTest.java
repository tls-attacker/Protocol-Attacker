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

import org.junit.jupiter.api.Test;

public class NoSignatureComputationsTest {

    @Test
    public void testConstructor() {
        // Verify that NoSignatureComputations can be instantiated
        NoSignatureComputations computations = new NoSignatureComputations();
        assertNotNull(computations);

        // Verify it inherits from SignatureComputations
        assertTrue(computations instanceof SignatureComputations);

        // Test inherited fields are initially null
        assertNull(computations.getSignatureBytes());
        assertNull(computations.getToBeSignedBytes());
        assertNull(computations.getDigestBytes());
        assertNull(computations.getSignatureValid());
    }

    @Test
    public void testInheritedMethods() {
        // Test inherited methods work correctly
        NoSignatureComputations computations = new NoSignatureComputations();
        byte[] testData = "test data".getBytes();

        // Test setters and getters
        computations.setSignatureBytes(testData);
        assertNotNull(computations.getSignatureBytes());
        assertNotNull(computations.getSignatureBytes().getValue());
        assertEquals(testData.length, computations.getSignatureBytes().getValue().length);

        computations.setToBeSignedBytes(testData);
        assertNotNull(computations.getToBeSignedBytes());
        assertNotNull(computations.getToBeSignedBytes().getValue());
        assertEquals(testData.length, computations.getToBeSignedBytes().getValue().length);

        computations.setDigestBytes(testData);
        assertNotNull(computations.getDigestBytes());
        assertNotNull(computations.getDigestBytes().getValue());
        assertEquals(testData.length, computations.getDigestBytes().getValue().length);

        computations.setSignatureValid(true);
        assertTrue(computations.getSignatureValid());
    }

    @Test
    public void testModifiableVariableSupport() {
        // Since NoSignatureComputations just extends SignatureComputations without
        // any additional functionality, we'll just test basic assignment works
        NoSignatureComputations computations = new NoSignatureComputations();
        byte[] testData = "test data".getBytes();

        // Test byte array setter works
        computations.setSignatureBytes(testData);
        assertNotNull(computations.getSignatureBytes());
        assertEquals(testData.length, computations.getSignatureBytes().getValue().length);
    }
}
