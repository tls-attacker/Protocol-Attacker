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
import de.rub.nds.protocol.constants.NamedEllipticCurveParameters;
import java.math.BigInteger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class EcdsaSignatureComputationsSimpleTest {

    private EcdsaSignatureComputations computations;
    private BigInteger testBigInt = new BigInteger("1234");

    @BeforeEach
    public void setUp() {
        computations = new EcdsaSignatureComputations();
    }

    @Test
    public void testBasicProperties() {
        assertNull(computations.getEcParameters());
        assertNull(computations.getHashAlgorithm());
        assertNull(computations.getPrivateKey());
        assertNull(computations.getNonce());
        assertNull(computations.getInverseNonce());
        assertNull(computations.getS());
        assertNull(computations.getR());
        assertNull(computations.getTruncatedHashBytes());
        assertNull(computations.getTruncatedHash());
    }

    @Test
    public void testSettersWithEnums() {
        // Test enum setters
        NamedEllipticCurveParameters params = NamedEllipticCurveParameters.SECP256R1;
        computations.setEcParameters(params);
        assertNotNull(computations.getEcParameters());
        assertEquals(params, computations.getEcParameters());

        computations.setHashAlgorithm(HashAlgorithm.SHA256);
        assertNotNull(computations.getHashAlgorithm());
        assertEquals(HashAlgorithm.SHA256, computations.getHashAlgorithm());
    }

    @Test
    public void testSettersWithBigInteger() {
        // Test BigInteger setters
        computations.setPrivateKey(testBigInt);
        assertNotNull(computations.getPrivateKey());
        assertEquals(testBigInt, computations.getPrivateKey().getValue());

        computations.setNonce(testBigInt);
        assertNotNull(computations.getNonce());
        assertEquals(testBigInt, computations.getNonce().getValue());

        computations.setInverseNonce(testBigInt);
        assertNotNull(computations.getInverseNonce());
        assertEquals(testBigInt, computations.getInverseNonce().getValue());

        computations.setS(testBigInt);
        assertNotNull(computations.getS());
        assertEquals(testBigInt, computations.getS().getValue());

        computations.setR(testBigInt);
        assertNotNull(computations.getR());
        assertEquals(testBigInt, computations.getR().getValue());

        computations.setTruncatedHash(testBigInt);
        assertNotNull(computations.getTruncatedHash());
        assertEquals(testBigInt, computations.getTruncatedHash().getValue());
    }

    @Test
    public void testByteArraySetter() {
        byte[] testBytes = "test".getBytes();
        computations.setTruncatedHashBytes(testBytes);
        assertNotNull(computations.getTruncatedHashBytes());
        assertEquals(testBytes.length, computations.getTruncatedHashBytes().getValue().length);
    }
}
