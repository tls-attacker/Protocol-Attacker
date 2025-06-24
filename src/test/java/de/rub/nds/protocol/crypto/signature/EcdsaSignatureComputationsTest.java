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
import de.rub.nds.protocol.constants.NamedEllipticCurveParameters;
import java.math.BigInteger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class EcdsaSignatureComputationsTest {

    private EcdsaSignatureComputations computations;
    private byte[] testData = "test data".getBytes();
    private BigInteger testBigInt = new BigInteger("12345678901234567890");

    @BeforeEach
    void setUp() {
        computations = new EcdsaSignatureComputations();
    }

    @Test
    void testTruncatedHashBytesGetterSetter() {
        // Initially null
        assertNull(computations.getTruncatedHashBytes());

        // Set and get with ModifiableByteArray
        ModifiableByteArray modifiableBytes = new ModifiableByteArray(testData);
        computations.setTruncatedHashBytes(modifiableBytes);
        assertEquals(modifiableBytes, computations.getTruncatedHashBytes());

        // Set and get with byte[]
        byte[] newData = "truncated hash bytes".getBytes();
        computations.setTruncatedHashBytes(newData);
        assertNotNull(computations.getTruncatedHashBytes());
        assertArrayEquals(newData, computations.getTruncatedHashBytes().getValue());
    }

    @Test
    void testTruncatedHashGetterSetter() {
        // Initially null
        assertNull(computations.getTruncatedHash());

        // Set and get with ModifiableBigInteger
        ModifiableBigInteger modifiableBigInt = new ModifiableBigInteger(testBigInt);
        computations.setTruncatedHash(modifiableBigInt);
        assertEquals(modifiableBigInt, computations.getTruncatedHash());

        // Set and get with BigInteger
        BigInteger newValue = new BigInteger("987654321");
        computations.setTruncatedHash(newValue);
        assertNotNull(computations.getTruncatedHash());
        assertEquals(newValue, computations.getTruncatedHash().getValue());
    }

    @Test
    void testEcParametersGetterSetter() {
        // Initially null
        assertNull(computations.getEcParameters());

        // Set and get
        NamedEllipticCurveParameters params = NamedEllipticCurveParameters.SECP256R1;
        computations.setEcParameters(params);
        assertEquals(params, computations.getEcParameters());
    }

    @Test
    void testHashAlgorithmGetterSetter() {
        // Initially null
        assertNull(computations.getHashAlgorithm());

        // Set and get
        computations.setHashAlgorithm(HashAlgorithm.SHA256);
        assertEquals(HashAlgorithm.SHA256, computations.getHashAlgorithm());
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
    void testNonceGetterSetter() {
        // Initially null
        assertNull(computations.getNonce());

        // Set and get with ModifiableBigInteger
        ModifiableBigInteger modifiableBigInt = new ModifiableBigInteger(testBigInt);
        computations.setNonce(modifiableBigInt);
        assertEquals(modifiableBigInt, computations.getNonce());

        // Set and get with BigInteger
        BigInteger newValue = new BigInteger("987654321");
        computations.setNonce(newValue);
        assertNotNull(computations.getNonce());
        assertEquals(newValue, computations.getNonce().getValue());
    }

    @Test
    void testInverseNonceGetterSetter() {
        // Initially null
        assertNull(computations.getInverseNonce());

        // Set and get with ModifiableBigInteger
        ModifiableBigInteger modifiableBigInt = new ModifiableBigInteger(testBigInt);
        computations.setInverseNonce(modifiableBigInt);
        assertEquals(modifiableBigInt, computations.getInverseNonce());

        // Set and get with BigInteger
        BigInteger newValue = new BigInteger("987654321");
        computations.setInverseNonce(newValue);
        assertNotNull(computations.getInverseNonce());
        assertEquals(newValue, computations.getInverseNonce().getValue());
    }

    @Test
    void testSGetterSetter() {
        // Initially null
        assertNull(computations.getS());

        // Set and get with ModifiableBigInteger
        ModifiableBigInteger modifiableBigInt = new ModifiableBigInteger(testBigInt);
        computations.setS(modifiableBigInt);
        assertEquals(modifiableBigInt, computations.getS());

        // Set and get with BigInteger
        BigInteger newValue = new BigInteger("987654321");
        computations.setS(newValue);
        assertNotNull(computations.getS());
        assertEquals(newValue, computations.getS().getValue());
    }

    @Test
    void testRGetterSetter() {
        // Initially null
        assertNull(computations.getR());

        // Set and get with ModifiableBigInteger
        ModifiableBigInteger modifiableBigInt = new ModifiableBigInteger(testBigInt);
        computations.setR(modifiableBigInt);
        assertEquals(modifiableBigInt, computations.getR());

        // Set and get with BigInteger
        BigInteger newValue = new BigInteger("987654321");
        computations.setR(newValue);
        assertNotNull(computations.getR());
        assertEquals(newValue, computations.getR().getValue());
    }
}
