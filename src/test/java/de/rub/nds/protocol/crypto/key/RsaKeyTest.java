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
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.rub.nds.protocol.constants.AsymmetricAlgorithmType;
import java.math.BigInteger;
import java.util.Random;
import org.apache.commons.lang3.tuple.Pair;
import org.junit.jupiter.api.Test;

public class RsaKeyTest {

    private static final Random RANDOM = new Random(42); // Fixed seed for reproducibility
    private static final BigInteger PUBLIC_EXPONENT = new BigInteger("65537");
    private static final BigInteger PRIVATE_EXPONENT = new BigInteger("3141592653589793");
    private static final BigInteger MODULUS = new BigInteger("9876543210123456789");

    @Test
    public void testRsaPrivateKey() {
        RsaPrivateKey privateKey = new RsaPrivateKey(PRIVATE_EXPONENT, MODULUS);

        assertEquals(PRIVATE_EXPONENT, privateKey.getPrivateExponent());
        assertEquals(MODULUS, privateKey.getModulus());
    }

    @Test
    public void testRsaPublicKeyConstruction() {
        RsaPublicKey publicKey = new RsaPublicKey(PUBLIC_EXPONENT, MODULUS);

        assertEquals(PUBLIC_EXPONENT, publicKey.getPublicExponent());
        assertEquals(MODULUS, publicKey.getModulus());
    }

    @Test
    public void testRsaPublicKeySetters() {
        RsaPublicKey publicKey = new RsaPublicKey(PUBLIC_EXPONENT, MODULUS);

        BigInteger newExponent = new BigInteger("17");
        BigInteger newModulus = new BigInteger("12345678901234567890");

        publicKey.setPublicExponent(newExponent);
        publicKey.setModulus(newModulus);

        assertEquals(newExponent, publicKey.getPublicExponent());
        assertEquals(newModulus, publicKey.getModulus());
    }

    @Test
    public void testRsaPublicKeyLength() {
        RsaPublicKey publicKey = new RsaPublicKey(PUBLIC_EXPONENT, MODULUS);
        assertEquals(MODULUS.bitLength(), publicKey.length());
    }

    @Test
    public void testRsaPublicKeyAlgorithmType() {
        RsaPublicKey publicKey = new RsaPublicKey(PUBLIC_EXPONENT, MODULUS);
        assertEquals(AsymmetricAlgorithmType.RSA, publicKey.getAlgorithmType());
    }

    @Test
    public void testRsaPublicKeyEqualsAndHashCode() {
        RsaPublicKey publicKey1 = new RsaPublicKey(PUBLIC_EXPONENT, MODULUS);
        RsaPublicKey publicKey2 = new RsaPublicKey(PUBLIC_EXPONENT, MODULUS);
        RsaPublicKey differentExponent =
                new RsaPublicKey(PUBLIC_EXPONENT.add(BigInteger.ONE), MODULUS);
        RsaPublicKey differentModulus =
                new RsaPublicKey(PUBLIC_EXPONENT, MODULUS.add(BigInteger.ONE));

        // Test equals
        assertTrue(publicKey1.equals(publicKey1)); // Same object
        assertTrue(publicKey1.equals(publicKey2)); // Equal objects
        assertFalse(publicKey1.equals(null)); // Null comparison
        assertFalse(publicKey1.equals(new Object())); // Different class
        assertFalse(publicKey1.equals(differentExponent)); // Different exponent
        assertFalse(publicKey1.equals(differentModulus)); // Different modulus

        // Test hashCode
        assertEquals(publicKey1.hashCode(), publicKey2.hashCode());
    }

    @Test
    public void testRsaKeyGeneration() {
        // Test with explicit exponent
        Pair<RsaPublicKey, RsaPrivateKey> keyPair1 =
                KeyGenerator.generateRsaKeys(PUBLIC_EXPONENT, 1024, RANDOM);

        assertNotNull(keyPair1);
        assertEquals(PUBLIC_EXPONENT, keyPair1.getLeft().getPublicExponent());
        assertEquals(1024, keyPair1.getLeft().getModulus().bitLength());
        assertEquals(keyPair1.getLeft().getModulus(), keyPair1.getRight().getModulus());

        // Test with default exponent
        Pair<RsaPublicKey, RsaPrivateKey> keyPair2 = KeyGenerator.generateRsaKeys(2048, RANDOM);

        assertNotNull(keyPair2);
        assertEquals(
                new BigInteger("65537"), keyPair2.getLeft().getPublicExponent()); // Default e=65537
        assertEquals(2048, keyPair2.getLeft().getModulus().bitLength());
        assertEquals(keyPair2.getLeft().getModulus(), keyPair2.getRight().getModulus());

        // Verify RSA key pair validity: e * d ≡ 1 (mod φ(n))
        // For testing, we'd need to know p and q to calculate φ(n) = (p-1)(q-1)
        // But we can check d*e mod phi = 1 indirectly with encryption/decryption test
        BigInteger testMessage = new BigInteger("12345");
        BigInteger encrypted =
                testMessage.modPow(
                        keyPair2.getLeft().getPublicExponent(), keyPair2.getLeft().getModulus());
        BigInteger decrypted =
                encrypted.modPow(
                        keyPair2.getRight().getPrivateExponent(), keyPair2.getRight().getModulus());

        assertEquals(testMessage, decrypted);
    }

    @Test
    public void testRsaKeyGenerationValidation() {
        // Test with too small bit length
        assertThrows(IllegalArgumentException.class, () -> KeyGenerator.generateRsaKeys(5, RANDOM));
    }
}
