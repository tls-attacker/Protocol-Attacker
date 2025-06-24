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

/**
 * Tests for the GostSignatureComputations class which implements GOST signature computation
 * support. This test covers the basic getter/setter functionality of the class.
 */
class GostSignatureComputationsTest {

    private GostSignatureComputations gostSignatureComputations;
    private static final BigInteger PRIVATE_KEY = new BigInteger("123456789");
    private static final BigInteger NONCE = new BigInteger("987654321");
    private static final BigInteger INVERSE_NONCE = new BigInteger("112233445566");
    private static final BigInteger R_X = new BigInteger("11223344");
    private static final BigInteger S = new BigInteger("55667788");
    private static final byte[] TRUNCATED_HASH_BYTES = new byte[] {0x01, 0x02, 0x03, 0x04};
    private static final BigInteger TRUNCATED_HASH = new BigInteger("1234");
    private static final NamedEllipticCurveParameters EC_PARAMETERS =
            NamedEllipticCurveParameters.SECP256R1;
    private static final HashAlgorithm HASH_ALGORITHM = HashAlgorithm.SHA256;

    @BeforeEach
    void setUp() {
        gostSignatureComputations = new GostSignatureComputations();
    }

    @Test
    void testGetterSetterEcParameters() {
        assertNull(gostSignatureComputations.getEcParameters());
        gostSignatureComputations.setEcParameters(EC_PARAMETERS);
        assertEquals(EC_PARAMETERS, gostSignatureComputations.getEcParameters());
    }

    @Test
    void testGetterSetterHashAlgorithm() {
        assertNull(gostSignatureComputations.getHashAlgorithm());
        gostSignatureComputations.setHashAlgorithm(HASH_ALGORITHM);
        assertEquals(HASH_ALGORITHM, gostSignatureComputations.getHashAlgorithm());
    }

    @Test
    void testGetterSetterPrivateKey() {
        assertNull(gostSignatureComputations.getPrivateKey());

        // Test BigInteger setter
        gostSignatureComputations.setPrivateKey(PRIVATE_KEY);
        assertNotNull(gostSignatureComputations.getPrivateKey());
        assertEquals(PRIVATE_KEY, gostSignatureComputations.getPrivateKey().getValue());
    }

    @Test
    void testGetterSetterNonce() {
        assertNull(gostSignatureComputations.getNonce());

        // Test BigInteger setter
        gostSignatureComputations.setNonce(NONCE);
        assertNotNull(gostSignatureComputations.getNonce());
        assertEquals(NONCE, gostSignatureComputations.getNonce().getValue());
    }

    @Test
    void testGetterSetterInverseNonce() {
        assertNull(gostSignatureComputations.getInverseNonce());

        // Test BigInteger setter
        gostSignatureComputations.setInverseNonce(INVERSE_NONCE);
        assertNotNull(gostSignatureComputations.getInverseNonce());
        assertEquals(INVERSE_NONCE, gostSignatureComputations.getInverseNonce().getValue());
    }

    @Test
    void testGetterSetterRX() {
        assertNull(gostSignatureComputations.getrX());

        // Test BigInteger setter
        gostSignatureComputations.setrX(R_X);
        assertNotNull(gostSignatureComputations.getrX());
        assertEquals(R_X, gostSignatureComputations.getrX().getValue());
    }

    @Test
    void testGetterSetterS() {
        assertNull(gostSignatureComputations.getS());

        // Test BigInteger setter
        gostSignatureComputations.setS(S);
        assertNotNull(gostSignatureComputations.getS());
        assertEquals(S, gostSignatureComputations.getS().getValue());
    }

    @Test
    void testGetterSetterTruncatedHashBytes() {
        assertNull(gostSignatureComputations.getTruncatedHashBytes());

        // Test byte[] setter
        gostSignatureComputations.setTruncatedHashBytes(TRUNCATED_HASH_BYTES);
        assertNotNull(gostSignatureComputations.getTruncatedHashBytes());
        assertEquals(
                TRUNCATED_HASH_BYTES.length,
                gostSignatureComputations.getTruncatedHashBytes().getValue().length);
    }

    @Test
    void testGetterSetterTruncatedHash() {
        assertNull(gostSignatureComputations.getTruncatedHash());

        // Test BigInteger setter
        gostSignatureComputations.setTruncatedHash(TRUNCATED_HASH);
        assertNotNull(gostSignatureComputations.getTruncatedHash());
        assertEquals(TRUNCATED_HASH, gostSignatureComputations.getTruncatedHash().getValue());
    }
}
