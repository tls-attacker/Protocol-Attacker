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
import java.math.BigInteger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class DsaSignatureComputationsTest {

    private DsaSignatureComputations computations;
    private byte[] testData = "test data".getBytes();
    private BigInteger testBigInt = new BigInteger("12345678901234567890");

    @BeforeEach
    void setUp() {
        computations = new DsaSignatureComputations();
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
    void testQGetterSetter() {
        // Initially null
        assertNull(computations.getQ());

        // Set and get with ModifiableBigInteger
        ModifiableBigInteger modifiableBigInt = new ModifiableBigInteger(testBigInt);
        computations.setQ(modifiableBigInt);
        assertEquals(modifiableBigInt, computations.getQ());

        // Set and get with BigInteger
        BigInteger newValue = new BigInteger("987654321");
        computations.setQ(newValue);
        assertNotNull(computations.getQ());
        assertEquals(newValue, computations.getQ().getValue());
    }

    @Test
    void testGGetterSetter() {
        // Initially null
        assertNull(computations.getG());

        // Set and get with ModifiableBigInteger
        ModifiableBigInteger modifiableBigInt = new ModifiableBigInteger(testBigInt);
        computations.setG(modifiableBigInt);
        assertEquals(modifiableBigInt, computations.getG());

        // Set and get with BigInteger
        BigInteger newValue = new BigInteger("987654321");
        computations.setG(newValue);
        assertNotNull(computations.getG());
        assertEquals(newValue, computations.getG().getValue());
    }

    @Test
    void testPGetterSetter() {
        // Initially null
        assertNull(computations.getP());

        // Set and get with ModifiableBigInteger
        ModifiableBigInteger modifiableBigInt = new ModifiableBigInteger(testBigInt);
        computations.setP(modifiableBigInt);
        assertEquals(modifiableBigInt, computations.getP());

        // Set and get with BigInteger
        BigInteger newValue = new BigInteger("987654321");
        computations.setP(newValue);
        assertNotNull(computations.getP());
        assertEquals(newValue, computations.getP().getValue());
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
    void testXrGetterSetter() {
        // Initially null
        assertNull(computations.getXr());

        // Set and get with ModifiableBigInteger
        ModifiableBigInteger modifiableBigInt = new ModifiableBigInteger(testBigInt);
        computations.setXr(modifiableBigInt);
        assertEquals(modifiableBigInt, computations.getXr());

        // Set and get with BigInteger
        BigInteger newValue = new BigInteger("987654321");
        computations.setXr(newValue);
        assertNotNull(computations.getXr());
        assertEquals(newValue, computations.getXr().getValue());
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
}
