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

import java.math.BigInteger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class DsaSignatureComputationsSimpleTest {

    private DsaSignatureComputations computations;
    private BigInteger testBigInt = new BigInteger("1234");

    @BeforeEach
    public void setUp() {
        computations = new DsaSignatureComputations();
    }

    @Test
    public void testBasicProperties() {
        assertNull(computations.getPrivateKey());
        assertNull(computations.getQ());
        assertNull(computations.getG());
        assertNull(computations.getP());
        assertNull(computations.getR());
        assertNull(computations.getS());
        assertNull(computations.getNonce());
        assertNull(computations.getInverseNonce());
        assertNull(computations.getXr());
        assertNull(computations.getTruncatedHashBytes());
    }

    @Test
    public void testSettersWithBigInteger() {
        // Test BigInteger setters
        computations.setPrivateKey(testBigInt);
        assertNotNull(computations.getPrivateKey());
        assertEquals(testBigInt, computations.getPrivateKey().getValue());

        computations.setQ(testBigInt);
        assertNotNull(computations.getQ());
        assertEquals(testBigInt, computations.getQ().getValue());

        computations.setG(testBigInt);
        assertNotNull(computations.getG());
        assertEquals(testBigInt, computations.getG().getValue());

        computations.setP(testBigInt);
        assertNotNull(computations.getP());
        assertEquals(testBigInt, computations.getP().getValue());

        computations.setR(testBigInt);
        assertNotNull(computations.getR());
        assertEquals(testBigInt, computations.getR().getValue());

        computations.setS(testBigInt);
        assertNotNull(computations.getS());
        assertEquals(testBigInt, computations.getS().getValue());

        computations.setNonce(testBigInt);
        assertNotNull(computations.getNonce());
        assertEquals(testBigInt, computations.getNonce().getValue());

        computations.setInverseNonce(testBigInt);
        assertNotNull(computations.getInverseNonce());
        assertEquals(testBigInt, computations.getInverseNonce().getValue());

        computations.setXr(testBigInt);
        assertNotNull(computations.getXr());
        assertEquals(testBigInt, computations.getXr().getValue());
    }

    @Test
    public void testByteArraySetter() {
        byte[] testBytes = "test".getBytes();
        computations.setTruncatedHashBytes(testBytes);
        assertNotNull(computations.getTruncatedHashBytes());
        assertEquals(testBytes.length, computations.getTruncatedHashBytes().getValue().length);
    }
}
