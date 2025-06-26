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
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.rub.nds.modifiablevariable.util.DataConverter;
import de.rub.nds.protocol.constants.HashAlgorithm;
import de.rub.nds.protocol.constants.NamedEllipticCurveParameters;
import de.rub.nds.protocol.constants.SignatureAlgorithm;
import de.rub.nds.protocol.crypto.key.GostPrivateKey;
import de.rub.nds.protocol.crypto.key.RsaPrivateKey;
import java.math.BigInteger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/** Test for GOST signature computation implementation. */
class GostSignatureCalculatorTest {

    private SignatureCalculator signatureCalculator;

    @BeforeEach
    void setUp() {
        signatureCalculator = new SignatureCalculator();
    }

    @Test
    void testGostSignatureComputationsCreation() {
        SignatureComputations computations =
                signatureCalculator.createSignatureComputations(SignatureAlgorithm.GOSTR34102001);
        assertNotNull(computations);
        assertTrue(computations instanceof GostSignatureComputations);

        computations =
                signatureCalculator.createSignatureComputations(
                        SignatureAlgorithm.GOSTR34102012_256);
        assertNotNull(computations);
        assertTrue(computations instanceof GostSignatureComputations);

        computations =
                signatureCalculator.createSignatureComputations(
                        SignatureAlgorithm.GOSTR34102012_512);
        assertNotNull(computations);
        assertTrue(computations instanceof GostSignatureComputations);
    }

    @Test
    void testGostSignatureWithWrongKeyType() {
        GostSignatureComputations computations = new GostSignatureComputations();
        RsaPrivateKey wrongKey = new RsaPrivateKey(BigInteger.TEN, BigInteger.TEN);
        byte[] toBeSignedBytes = new byte[] {0x01, 0x02, 0x03};

        assertThrows(
                IllegalArgumentException.class,
                () ->
                        signatureCalculator.computeSignature(
                                computations,
                                wrongKey,
                                toBeSignedBytes,
                                SignatureAlgorithm.GOSTR34102001,
                                HashAlgorithm.SHA256));
    }

    @Test
    void testGost2001SetASignature() {
        // Test vector based on GOST R 34.10-2001 standard
        // Using test parameters from the standard
        BigInteger privateKey =
                new BigInteger(
                        "55441196065363246126355624130324183196576709222340016572108097750006097525544");
        BigInteger nonce =
                new BigInteger(
                        "53854137677348463731403841147996619241504003434302020712960838528893196233395");

        GostPrivateKey gostKey =
                new GostPrivateKey(privateKey, nonce, NamedEllipticCurveParameters.GOST2001_SETA);

        GostSignatureComputations computations = new GostSignatureComputations();
        byte[] message =
                DataConverter.hexStringToByteArray(
                        "2dfbc1b372d89a1188c09c52e0eec61fce52032ab1022e8e67ece6672b043ee5");

        signatureCalculator.computeGostSignature(
                computations, gostKey, message, HashAlgorithm.NONE);

        assertNotNull(computations.getSignatureBytes());
        assertEquals(64, computations.getSignatureBytes().getValue().length);
        assertTrue(computations.getSignatureValid());
        assertNotNull(computations.getrX());
        assertNotNull(computations.getS());
    }

    @Test
    void testGost2012SetA256Signature() {
        // Test parameters for GOST R 34.10-2012 256-bit
        BigInteger privateKey =
                new BigInteger(
                        "55441196065363246126355624130324183196576709222340016572108097750006097525544");
        BigInteger nonce =
                new BigInteger(
                        "53854137677348463731403841147996619241504003434302020712960838528893196233395");

        GostPrivateKey gostKey =
                new GostPrivateKey(
                        privateKey, nonce, NamedEllipticCurveParameters.GOST2012_SETA256);

        GostSignatureComputations computations = new GostSignatureComputations();
        byte[] message = "Test message for GOST signature".getBytes();

        signatureCalculator.computeGostSignature(
                computations, gostKey, message, HashAlgorithm.SHA256);

        assertNotNull(computations.getSignatureBytes());
        assertEquals(64, computations.getSignatureBytes().getValue().length);
        assertTrue(computations.getSignatureValid());
        assertNotNull(computations.getrX());
        assertNotNull(computations.getS());
        assertNotNull(computations.getDigestBytes());
        assertEquals(32, computations.getDigestBytes().getValue().length);
    }

    @Test
    void testGost2012SetA512Signature() {
        // Test parameters for GOST R 34.10-2012 512-bit
        BigInteger privateKey =
                new BigInteger(
                        "55441196065363246126355624130324183196576709222340016572108097750006097525544");
        BigInteger nonce =
                new BigInteger(
                        "53854137677348463731403841147996619241504003434302020712960838528893196233395");

        GostPrivateKey gostKey =
                new GostPrivateKey(
                        privateKey, nonce, NamedEllipticCurveParameters.GOST2012_SETA512);

        GostSignatureComputations computations = new GostSignatureComputations();
        byte[] message = "Test message for GOST 512-bit signature".getBytes();

        signatureCalculator.computeGostSignature(
                computations, gostKey, message, HashAlgorithm.SHA512);

        assertNotNull(computations.getSignatureBytes());
        assertEquals(128, computations.getSignatureBytes().getValue().length);
        assertTrue(computations.getSignatureValid());
        assertNotNull(computations.getrX());
        assertNotNull(computations.getS());
        assertNotNull(computations.getDigestBytes());
        assertEquals(64, computations.getDigestBytes().getValue().length);
    }

    @Test
    void testGostSignatureZeroHashHandling() {
        // Test the special case where e = 0 (should be set to 1)
        BigInteger privateKey = BigInteger.ONE;
        BigInteger nonce = BigInteger.valueOf(2);

        GostPrivateKey gostKey =
                new GostPrivateKey(privateKey, nonce, NamedEllipticCurveParameters.GOST2001_SETA);

        GostSignatureComputations computations = new GostSignatureComputations();
        // A message that would produce hash = 0 (simulated with NONE hash)
        byte[] message = new byte[32]; // All zeros

        signatureCalculator.computeGostSignature(
                computations, gostKey, message, HashAlgorithm.NONE);

        // When e = 0, it should be set to 1
        assertEquals(BigInteger.ONE, computations.getTruncatedHash().getValue());
        assertNotNull(computations.getSignatureBytes());
        assertTrue(computations.getSignatureValid());
    }

    @Test
    void testGostSignatureLittleEndianFormat() {
        // Test that the signature is properly formatted in little-endian
        BigInteger privateKey = BigInteger.valueOf(12345);
        BigInteger nonce = BigInteger.valueOf(67890);

        GostPrivateKey gostKey =
                new GostPrivateKey(privateKey, nonce, NamedEllipticCurveParameters.GOST2001_SETA);

        GostSignatureComputations computations = new GostSignatureComputations();
        byte[] message = "Test little-endian format".getBytes();

        signatureCalculator.computeGostSignature(
                computations, gostKey, message, HashAlgorithm.SHA256);

        byte[] signature = computations.getSignatureBytes().getValue();
        assertNotNull(signature);
        assertEquals(64, signature.length); // 32 bytes for s + 32 bytes for r

        // The signature should be s||r in little-endian format
        byte[] sBytes = new byte[32];
        byte[] rBytes = new byte[32];
        System.arraycopy(signature, 0, sBytes, 0, 32);
        System.arraycopy(signature, 32, rBytes, 0, 32);

        // Verify that we can reconstruct s and r
        // Reverse bytes for big-endian interpretation
        byte[] sReversed = new byte[32];
        byte[] rReversed = new byte[32];
        for (int i = 0; i < 32; i++) {
            sReversed[i] = sBytes[31 - i];
            rReversed[i] = rBytes[31 - i];
        }

        BigInteger sRecovered = new BigInteger(1, sReversed);
        BigInteger rRecovered = new BigInteger(1, rReversed);

        assertEquals(computations.getS().getValue(), sRecovered);
        assertEquals(computations.getrX().getValue(), rRecovered);
    }

    @Test
    void testComputeSignatureWithGostAlgorithm() {
        // Test the main computeSignature method with GOST algorithm
        BigInteger privateKey = BigInteger.valueOf(99999);
        BigInteger nonce = BigInteger.valueOf(11111);

        GostPrivateKey gostKey =
                new GostPrivateKey(privateKey, nonce, NamedEllipticCurveParameters.GOST2001_SETA);

        GostSignatureComputations computations = new GostSignatureComputations();
        byte[] message = "Integration test message".getBytes();

        signatureCalculator.computeSignature(
                computations,
                gostKey,
                message,
                SignatureAlgorithm.GOSTR34102001,
                HashAlgorithm.SHA256);

        assertNotNull(computations.getSignatureBytes());
        assertTrue(computations.getSignatureValid());
        assertEquals(64, computations.getSignatureBytes().getValue().length);
    }
}
