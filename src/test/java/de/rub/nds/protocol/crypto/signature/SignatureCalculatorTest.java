/*
 * Protocol-Attacker - A framework to create protocol analysis tools
 *
 * Copyright 2023-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.protocol.crypto.signature;

import static org.junit.jupiter.api.Assertions.*;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.protocol.constants.HashAlgorithm;
import de.rub.nds.protocol.constants.NamedEllipticCurveParameters;
import java.math.BigInteger;
import org.junit.jupiter.api.Test;

/**
 * @author robertmerget
 */
public class SignatureCalculatorTest {

    /**
     * Test of computeRsaPkcs1Signature method, of class SignatureCalculator.
     */
    @Test
    public void testComputeRsaPkcs1Signature() {
        RsaPkcs1SignatureComputations computations = new RsaPkcs1SignatureComputations();
        BigInteger modulus
                = new BigInteger(1, ArrayConverter.hexStringToByteArray(
                        "00cbfb45e6b09f1af40df60ddc865b6f98a1fd724678b583bfb5ae8539627bffdcd930d7c3f996f75e15172a017f143101ecd28fc629b800e24f0a83665d77c0a3"));
        BigInteger privateKey
                = new BigInteger(1, ArrayConverter.hexStringToByteArray(
                        "61a4eb153f3f2a9be18303a7a8f964366074fe9b15756e97fad48c19a8374b870589dde72e4377f3837ab59fa76b55563642f2df635da71a3aa50ab835201b61"));
        byte[] toBeSignedBytes = "abcdefghijklmnopqrstuvwxyz\n".getBytes();
        HashAlgorithm hashAlgorithm = HashAlgorithm.SHA1;
        SignatureCalculator instance = new SignatureCalculator();
        instance.computeRsaPkcs1Signature(
                computations, privateKey, modulus, toBeSignedBytes, hashAlgorithm);
        assertArrayEquals(toBeSignedBytes, computations.getToBeSignedBytes().getValue());

        assertArrayEquals(
                ArrayConverter.hexStringToByteArray("8c723a0fa70b111017b4a6f06afe1c0dbcec14e3"),
                computations.getDigestBytes().getValue());
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray(
                        "3021300906052b0e03021a050004148c723a0fa70b111017b4a6f06afe1c0dbcec14e3"),
                computations.getDerEncodedDigest().getValue());

        assertEquals(HashAlgorithm.SHA1, computations.getHashAlgorithm());
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray(
                        "0001ffffffffffffffffffffffffffffffffffffffffffffffffffff00"),
                computations.getPadding().getValue());
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray(
                        "0001ffffffffffffffffffffffffffffffffffffffffffffffffffff003021300906052b0e03021a050004148c723a0fa70b111017b4a6f06afe1c0dbcec14e3"),
                computations.getPlainToBeSigned().getValue());
        System.out.println(
                ArrayConverter.bytesToHexString(computations.getSignatureBytes().getValue()));
        
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray(
                        "9139be98f16cf53d22da63cb559bb06a93338da6a344e28a4285c2da33facb7080d26e7a09483779a016eebc207602fc3f90492c2f2fb8143f0fe30fd855593d"),
                computations.getSignatureBytes().getValue());
        assertArrayEquals(toBeSignedBytes, computations.getToBeSignedBytes().getValue());
        assertEquals(modulus, computations.getModulus().getValue());
        assertEquals(privateKey, computations.getPrivateKey().getValue());
        assertTrue(computations.getSignatureValid());
    }

    /**
     * Test of computeDsaSignature method, of class SignatureCalculator.
     */
    @Test
    public void testComputeDsaSignature() {
        DsaSignatureComputations computations = null;
        BigInteger privateKey = null;
        byte[] toBeSignedBytes = null;
        BigInteger nonce = null;
        BigInteger q = null;
        BigInteger g = null;
        BigInteger p = null;
        HashAlgorithm hashAlgorithm = null;
        SignatureCalculator instance = new SignatureCalculator();
        instance.computeDsaSignature(
                computations, privateKey, toBeSignedBytes, nonce, q, g, p, hashAlgorithm);
        // TODO review the generated test code and remove the default call to fail.
        fail("The test case is a prototype.");
    }

    /**
     * Test of computeEcdsaSignature method, of class SignatureCalculator.
     */
    @Test
    public void testComputeEcdsaSignature() {
        EcdsaSignatureComputations computations = null;
        BigInteger privateKey = null;
        byte[] toBeSignedBytes = null;
        BigInteger nonce = null;
        NamedEllipticCurveParameters ecParameters = null;
        HashAlgorithm hashAlgorithm = null;
        SignatureCalculator instance = new SignatureCalculator();
        instance.computeEcdsaSignature(
                computations, privateKey, toBeSignedBytes, nonce, ecParameters, hashAlgorithm);
        // TODO review the generated test code and remove the default call to fail.
        fail("The test case is a prototype.");
    }
}
