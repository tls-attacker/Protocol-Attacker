/*
 * Protocol-Attacker - A Framework to create Protocol Analysis Tools
 *
 * Copyright 2023-2024 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.protocol.crypto.signature;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

import de.rub.nds.modifiablevariable.biginteger.ModifiableBigInteger;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.protocol.constants.HashAlgorithm;
import java.math.BigInteger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class RsaSsaPssSignatureComputationsTest {

    private RsaSsaPssSignatureComputations computations;
    private byte[] testData = "test data".getBytes();
    private BigInteger testBigInt = new BigInteger("12345678901234567890");

    @BeforeEach
    void setUp() {
        computations = new RsaSsaPssSignatureComputations();
    }

    @Test
    void testPrivateKeyGetterSetter() {
        // Initially null
        assertNull(computations.getPrivateKey());

        // Set and get with ModifiableBigInteger
        ModifiableBigInteger modifiableBigInt = new ModifiableBigInteger(testBigInt);
        computations.setPrivateKey(modifiableBigInt);
        assertEquals(modifiableBigInt, computations.getPrivateKey());

        // Set and get with BigInteger
        BigInteger newValue = new BigInteger("987654321");
        computations.setPrivateKey(newValue);
        assertNotNull(computations.getPrivateKey());
        assertEquals(newValue, computations.getPrivateKey().getValue());
    }

    @Test
    void testModulusGetterSetter() {
        // Initially null
        assertNull(computations.getModulus());

        // Set and get with ModifiableBigInteger
        ModifiableBigInteger modifiableBigInt = new ModifiableBigInteger(testBigInt);
        computations.setModulus(modifiableBigInt);
        assertEquals(modifiableBigInt, computations.getModulus());

        // Set and get with BigInteger
        BigInteger newValue = new BigInteger("987654321");
        computations.setModulus(newValue);
        assertNotNull(computations.getModulus());
        assertEquals(newValue, computations.getModulus().getValue());
    }

    @Test
    void testPlainToBeSignedGetterSetter() {
        // Initially null
        assertNull(computations.getPlainToBeSigned());

        // Set and get with ModifiableByteArray
        ModifiableByteArray modifiableBytes = new ModifiableByteArray(testData);
        computations.setPlainToBeSigned(modifiableBytes);
        assertEquals(modifiableBytes, computations.getPlainToBeSigned());

        // Set and get with byte[]
        byte[] newData = "new plain data".getBytes();
        computations.setPlainToBeSigned(newData);
        assertNotNull(computations.getPlainToBeSigned());
        assertArrayEquals(newData, computations.getPlainToBeSigned().getValue());
    }

    @Test
    void testSaltGetterSetter() {
        // Initially null
        assertNull(computations.getSalt());

        // Set and get with ModifiableByteArray
        ModifiableByteArray modifiableBytes = new ModifiableByteArray(testData);
        computations.setSalt(modifiableBytes);
        assertEquals(modifiableBytes, computations.getSalt());

        // Set and get with byte[]
        byte[] newData = "salt data".getBytes();
        computations.setSalt(newData);
        assertNotNull(computations.getSalt());
        assertArrayEquals(newData, computations.getSalt().getValue());
    }

    @Test
    void testPaddedSaltedDigestGetterSetter() {
        // Initially null
        assertNull(computations.getPaddedSaltedDigest());

        // Set and get with ModifiableByteArray
        ModifiableByteArray modifiableBytes = new ModifiableByteArray(testData);
        computations.setPaddedSaltedDigest(modifiableBytes);
        assertEquals(modifiableBytes, computations.getPaddedSaltedDigest());

        // Set and get with byte[]
        byte[] newData = "padded salted digest".getBytes();
        computations.setPaddedSaltedDigest(newData);
        assertNotNull(computations.getPaddedSaltedDigest());
        assertArrayEquals(newData, computations.getPaddedSaltedDigest().getValue());
    }

    @Test
    void testHValueGetterSetter() {
        // Initially null
        assertNull(computations.getHValue());

        // Set and get with ModifiableByteArray
        ModifiableByteArray modifiableBytes = new ModifiableByteArray(testData);
        computations.setHValue(modifiableBytes);
        assertEquals(modifiableBytes, computations.getHValue());

        // Set and get with byte[]
        byte[] newData = "h value".getBytes();
        computations.setHValue(newData);
        assertNotNull(computations.getHValue());
        assertArrayEquals(newData, computations.getHValue().getValue());
    }

    @Test
    void testPsValueGetterSetter() {
        // Initially null
        assertNull(computations.getPsValue());

        // Set and get with ModifiableByteArray
        ModifiableByteArray modifiableBytes = new ModifiableByteArray(testData);
        computations.setPsValue(modifiableBytes);
        assertEquals(modifiableBytes, computations.getPsValue());

        // Set and get with byte[]
        byte[] newData = "ps value".getBytes();
        computations.setPsValue(newData);
        assertNotNull(computations.getPsValue());
        assertArrayEquals(newData, computations.getPsValue().getValue());
    }

    @Test
    void testDbValueGetterSetter() {
        // Initially null
        assertNull(computations.getDbValue());

        // Set and get with ModifiableByteArray
        ModifiableByteArray modifiableBytes = new ModifiableByteArray(testData);
        computations.setDbValue(modifiableBytes);
        assertEquals(modifiableBytes, computations.getDbValue());

        // Set and get with byte[]
        byte[] newData = "db value".getBytes();
        computations.setDbValue(newData);
        assertNotNull(computations.getDbValue());
        assertArrayEquals(newData, computations.getDbValue().getValue());
    }

    @Test
    void testMaskedDbGetterSetter() {
        // Initially null
        assertNull(computations.getMaskedDb());

        // Set and get with ModifiableByteArray
        ModifiableByteArray modifiableBytes = new ModifiableByteArray(testData);
        computations.setMaskedDb(modifiableBytes);
        assertEquals(modifiableBytes, computations.getMaskedDb());

        // Set and get with byte[]
        byte[] newData = "masked db".getBytes();
        computations.setMaskedDb(newData);
        assertNotNull(computations.getMaskedDb());
        assertArrayEquals(newData, computations.getMaskedDb().getValue());
    }

    @Test
    void testEmValueGetterSetter() {
        // Initially null
        assertNull(computations.getEmValue());

        // Set and get with ModifiableByteArray
        ModifiableByteArray modifiableBytes = new ModifiableByteArray(testData);
        computations.setEmValue(modifiableBytes);
        assertEquals(modifiableBytes, computations.getEmValue());

        // Set and get with byte[]
        byte[] newData = "em value".getBytes();
        computations.setEmValue(newData);
        assertNotNull(computations.getEmValue());
        assertArrayEquals(newData, computations.getEmValue().getValue());
    }

    @Test
    void testTfValueGetterSetter() {
        // Initially null
        assertNull(computations.getTfValue());

        // Set and get with ModifiableByteArray
        ModifiableByteArray modifiableBytes = new ModifiableByteArray(testData);
        computations.setTfValue(modifiableBytes);
        assertEquals(modifiableBytes, computations.getTfValue());

        // Set and get with byte[]
        byte[] newData = "tf value".getBytes();
        computations.setTfValue(newData);
        assertNotNull(computations.getTfValue());
        assertArrayEquals(newData, computations.getTfValue().getValue());
    }

    @Test
    void testHashAlgorithmGetterSetter() {
        // Initially null
        assertNull(computations.getHashAlgorithm());

        // Set and get
        computations.setHashAlgorithm(HashAlgorithm.SHA256);
        assertEquals(HashAlgorithm.SHA256, computations.getHashAlgorithm());
    }
}
