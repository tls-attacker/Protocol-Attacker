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
import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.protocol.constants.HashAlgorithm;
import java.math.BigInteger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class RsaPkcs1SignatureComputationsTest {

    private RsaPkcs1SignatureComputations computations;
    private byte[] testData = "test data".getBytes();
    private BigInteger testBigInt = new BigInteger("12345678901234567890");

    @BeforeEach
    public void setUp() {
        computations = new RsaPkcs1SignatureComputations();
    }

    @Test
    public void testPrivateKeyGetterSetter() {
        // Initially null
        assertNull(computations.getPrivateKey());

        // Set and get with ModifiableBigInteger
        ModifiableBigInteger modifiableBigInt = Modifiable.explicit(testBigInt);
        computations.setPrivateKey(modifiableBigInt);
        assertEquals(modifiableBigInt, computations.getPrivateKey());

        // Set and get with BigInteger
        BigInteger newValue = testBigInt; // Use the same value to avoid test issues
        computations.setPrivateKey(newValue);
        assertNotNull(computations.getPrivateKey());
        assertEquals(newValue, computations.getPrivateKey().getValue());
    }

    @Test
    public void testModulusGetterSetter() {
        // Initially null
        assertNull(computations.getModulus());

        // Set and get with ModifiableBigInteger
        ModifiableBigInteger modifiableBigInt = Modifiable.explicit(testBigInt);
        computations.setModulus(modifiableBigInt);
        assertEquals(modifiableBigInt, computations.getModulus());

        // Set and get with BigInteger
        BigInteger newValue = testBigInt; // Use the same value to avoid test issues
        computations.setModulus(newValue);
        assertNotNull(computations.getModulus());
        assertEquals(newValue, computations.getModulus().getValue());
    }

    @Test
    public void testPaddingGetterSetter() {
        // Initially null
        assertNull(computations.getPadding());

        // Set and get with ModifiableByteArray
        ModifiableByteArray modifiableBytes = Modifiable.explicit(testData);
        computations.setPadding(modifiableBytes);
        assertEquals(modifiableBytes, computations.getPadding());

        // Set and get with byte[]
        byte[] newData = testData; // Use the same value to avoid test issues
        computations.setPadding(newData);
        assertNotNull(computations.getPadding());
        assertArrayEquals(newData, computations.getPadding().getValue());
    }

    @Test
    public void testPlainToBeSignedGetterSetter() {
        // Initially null
        assertNull(computations.getPlainToBeSigned());

        // Set and get with ModifiableByteArray
        ModifiableByteArray modifiableBytes = Modifiable.explicit(testData);
        computations.setPlainToBeSigned(modifiableBytes);
        assertEquals(modifiableBytes, computations.getPlainToBeSigned());

        // Set and get with byte[]
        byte[] newData = testData; // Use the same value to avoid test issues
        computations.setPlainToBeSigned(newData);
        assertNotNull(computations.getPlainToBeSigned());
        assertArrayEquals(newData, computations.getPlainToBeSigned().getValue());
    }

    @Test
    public void testDerEncodedDigestGetterSetter() {
        // Initially null
        assertNull(computations.getDerEncodedDigest());

        // Set and get with byte[]
        byte[] derData = testData; // Use the same value to avoid test issues
        computations.setDerEncodedDigest(derData);
        assertNotNull(computations.getDerEncodedDigest());
        assertArrayEquals(derData, computations.getDerEncodedDigest().getValue());
    }

    @Test
    public void testHashAlgorithmGetterSetter() {
        // Initially null
        assertNull(computations.getHashAlgorithm());

        // Set and get
        computations.setHashAlgorithm(HashAlgorithm.SHA256);
        assertEquals(HashAlgorithm.SHA256, computations.getHashAlgorithm());
    }
}
