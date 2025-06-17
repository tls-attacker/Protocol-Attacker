/*
 * Protocol-Attacker - A Framework to create Protocol Analysis Tools
 *
 * Copyright 2023-2024 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.protocol.crypto.key;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.rub.nds.protocol.constants.AsymmetricAlgorithmType;
import de.rub.nds.protocol.constants.FfdhGroupParameters;
import de.rub.nds.protocol.crypto.ffdh.ExplicitFfdhGroupParameters;
import de.rub.nds.protocol.crypto.ffdh.Rfc7919Group2048;
import java.math.BigInteger;
import java.util.Random;
import org.junit.jupiter.api.Test;

public class DhKeyTest {

    private static final Random RANDOM = new Random(42); // Fixed seed for reproducibility
    private static final BigInteger PRIVATE_KEY = new BigInteger("1234567890");
    private static final BigInteger GENERATOR = BigInteger.valueOf(2);
    private static final BigInteger MODULUS = new BigInteger("7919", 10); // Small prime for testing

    @Test
    public void testDhPrivateKey() {
        FfdhGroupParameters parameters = new ExplicitFfdhGroupParameters(GENERATOR, MODULUS);
        DhPrivateKey privateKey = new DhPrivateKey(PRIVATE_KEY, parameters);

        assertEquals(PRIVATE_KEY, privateKey.getPrivateKey());
        assertEquals(parameters, privateKey.getParameters());
        assertEquals(GENERATOR, privateKey.getParameters().getGenerator());
        assertEquals(MODULUS, privateKey.getParameters().getModulus());
    }

    @Test
    public void testDhPublicKeyConstruction() {
        // Test constructor with explicit generator and modulus
        DhPublicKey publicKey1 = new DhPublicKey(PRIVATE_KEY, GENERATOR, MODULUS);
        assertEquals(PRIVATE_KEY, publicKey1.getPublicKey());
        assertEquals(GENERATOR, publicKey1.getGenerator());
        assertEquals(MODULUS, publicKey1.getModulus());

        // Test constructor with parameters
        FfdhGroupParameters parameters = new ExplicitFfdhGroupParameters(GENERATOR, MODULUS);
        DhPublicKey publicKey2 = new DhPublicKey(PRIVATE_KEY, parameters);
        assertEquals(PRIVATE_KEY, publicKey2.getPublicKey());
        assertEquals(GENERATOR, publicKey2.getGenerator());
        assertEquals(MODULUS, publicKey2.getModulus());
    }

    @Test
    public void testDhPublicKeyLength() {
        DhPublicKey publicKey = new DhPublicKey(PRIVATE_KEY, GENERATOR, MODULUS);
        assertEquals(MODULUS.bitLength(), publicKey.length());
    }

    @Test
    public void testDhPublicKeyAlgorithmType() {
        DhPublicKey publicKey = new DhPublicKey(PRIVATE_KEY, GENERATOR, MODULUS);
        assertEquals(AsymmetricAlgorithmType.DH, publicKey.getAlgorithmType());
    }

    @Test
    public void testDhPublicKeyEqualsAndHashCode() {
        DhPublicKey publicKey1 = new DhPublicKey(PRIVATE_KEY, GENERATOR, MODULUS);
        DhPublicKey publicKey2 = new DhPublicKey(PRIVATE_KEY, GENERATOR, MODULUS);
        DhPublicKey differentPublicKey =
                new DhPublicKey(PRIVATE_KEY.add(BigInteger.ONE), GENERATOR, MODULUS);

        // Test equals
        assertTrue(publicKey1.equals(publicKey1)); // Same object
        assertTrue(publicKey1.equals(publicKey2)); // Equal objects
        assertFalse(publicKey1.equals(null)); // Null comparison
        assertFalse(publicKey1.equals(new Object())); // Different class
        assertFalse(publicKey1.equals(differentPublicKey)); // Different public key value

        // Test hashCode
        assertEquals(publicKey1.hashCode(), publicKey2.hashCode());
    }

    @Test
    public void testKeyGenerationWithParameters() {
        FfdhGroupParameters parameters = new Rfc7919Group2048();
        BigInteger privateKey = new BigInteger(parameters.getElementSizeBits(), RANDOM);
        DhPublicKey publicKey = KeyGenerator.generateDhPublicKey(privateKey, parameters);

        assertNotNull(publicKey);
        assertEquals(parameters.getGenerator(), publicKey.getGenerator());
        assertEquals(parameters.getModulus(), publicKey.getModulus());

        // The public key should be valid
        assertNotNull(publicKey.getPublicKey());
    }

    @Test
    public void testKeyGenerationWithExplicitParameters() {
        BigInteger privateKey = new BigInteger(64, RANDOM);
        DhPublicKey publicKey = KeyGenerator.generateDhPublicKey(privateKey, GENERATOR, MODULUS);

        assertNotNull(publicKey);
        assertEquals(GENERATOR, publicKey.getGenerator());
        assertEquals(MODULUS, publicKey.getModulus());

        // The public key should be valid
        assertNotNull(publicKey.getPublicKey());
    }

    @Test
    public void testKeyGenerationWithBitLength() {
        BigInteger privateKey = new BigInteger(64, RANDOM);
        int bitLength = 512;
        DhPublicKey publicKey = KeyGenerator.generateDhPublicKey(privateKey, bitLength, RANDOM);

        assertNotNull(publicKey);
        assertEquals(BigInteger.valueOf(2), publicKey.getGenerator()); // Hardcoded generator
        // Bit length may not be exact due to leading zeros
        assertTrue(publicKey.getModulus().bitLength() <= bitLength);
        assertTrue(publicKey.getModulus().bitLength() >= bitLength - 8);

        // The public key should be valid
        assertNotNull(publicKey.getPublicKey());
    }
}
