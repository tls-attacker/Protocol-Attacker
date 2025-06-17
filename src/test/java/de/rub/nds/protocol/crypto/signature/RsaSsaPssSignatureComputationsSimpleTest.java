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

import de.rub.nds.protocol.constants.HashAlgorithm;
import java.math.BigInteger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class RsaSsaPssSignatureComputationsSimpleTest {

    private RsaSsaPssSignatureComputations computations;
    private BigInteger testBigInt = new BigInteger("1234");
    private byte[] testBytes = "test data".getBytes();

    @BeforeEach
    public void setUp() {
        computations = new RsaSsaPssSignatureComputations();
    }

    @Test
    public void testBasicProperties() {
        assertNull(computations.getPrivateKey());
        assertNull(computations.getModulus());
        assertNull(computations.getPlainToBeSigned());
        assertNull(computations.getSalt());
        assertNull(computations.getPaddedSaltedDigest());
        assertNull(computations.getHValue());
        assertNull(computations.getPsValue());
        assertNull(computations.getDbValue());
        assertNull(computations.getMaskedDb());
        assertNull(computations.getEmValue());
        assertNull(computations.getTfValue());
        assertNull(computations.getHashAlgorithm());
    }

    @Test
    public void testHashAlgorithmSetter() {
        computations.setHashAlgorithm(HashAlgorithm.SHA256);
        assertNotNull(computations.getHashAlgorithm());
        assertEquals(HashAlgorithm.SHA256, computations.getHashAlgorithm());
    }

    @Test
    public void testBigIntegerSetters() {
        // Test BigInteger setters
        computations.setPrivateKey(testBigInt);
        assertNotNull(computations.getPrivateKey());
        assertEquals(testBigInt, computations.getPrivateKey().getValue());

        computations.setModulus(testBigInt);
        assertNotNull(computations.getModulus());
        assertEquals(testBigInt, computations.getModulus().getValue());
    }

    @Test
    public void testByteArraySetters() {
        // Test byte array setters
        computations.setPlainToBeSigned(testBytes);
        assertNotNull(computations.getPlainToBeSigned());
        assertEquals(testBytes.length, computations.getPlainToBeSigned().getValue().length);

        computations.setSalt(testBytes);
        assertNotNull(computations.getSalt());
        assertEquals(testBytes.length, computations.getSalt().getValue().length);

        computations.setPaddedSaltedDigest(testBytes);
        assertNotNull(computations.getPaddedSaltedDigest());
        assertEquals(testBytes.length, computations.getPaddedSaltedDigest().getValue().length);

        computations.setHValue(testBytes);
        assertNotNull(computations.getHValue());
        assertEquals(testBytes.length, computations.getHValue().getValue().length);

        computations.setPsValue(testBytes);
        assertNotNull(computations.getPsValue());
        assertEquals(testBytes.length, computations.getPsValue().getValue().length);

        computations.setDbValue(testBytes);
        assertNotNull(computations.getDbValue());
        assertEquals(testBytes.length, computations.getDbValue().getValue().length);

        computations.setMaskedDb(testBytes);
        assertNotNull(computations.getMaskedDb());
        assertEquals(testBytes.length, computations.getMaskedDb().getValue().length);

        computations.setEmValue(testBytes);
        assertNotNull(computations.getEmValue());
        assertEquals(testBytes.length, computations.getEmValue().getValue().length);

        computations.setTfValue(testBytes);
        assertNotNull(computations.getTfValue());
        assertEquals(testBytes.length, computations.getTfValue().getValue().length);
    }
}
