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
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.rub.nds.protocol.constants.AsymmetricAlgorithmType;
import java.math.BigInteger;
import java.util.Random;
import org.junit.jupiter.api.Test;

class DsaKeyTest {

    private static final Random RANDOM = new Random(42); // Fixed seed for reproducibility
    private static final BigInteger Q = new BigInteger("127", 10); // Small prime for q
    private static final BigInteger P = new BigInteger("7919", 10); // Small prime for p
    private static final BigInteger G = new BigInteger("2", 10); // Generator
    private static final BigInteger X = new BigInteger("57", 10); // Private key
    private static final BigInteger Y = G.modPow(X, P); // Public key

    @Test
    void testDsaPrivateKey() {
        // Create a nonce value
        BigInteger k = new BigInteger("123", 10);
        DsaPrivateKey privateKey = new DsaPrivateKey(Q, X, k, G, P);

        assertEquals(Q, privateKey.getQ());
        assertEquals(X, privateKey.getX());
        assertEquals(k, privateKey.getK());
        assertEquals(G, privateKey.getGenerator());
        assertEquals(P, privateKey.getModulus());
    }

    @Test
    void testDsaPublicKeyConstruction() {
        DsaPublicKey publicKey = new DsaPublicKey(Q, Y, G, P);

        assertEquals(Q, publicKey.getQ());
        assertEquals(Y, publicKey.getY());
        assertEquals(G, publicKey.getGenerator());
        assertEquals(P, publicKey.getModulus());
    }

    @Test
    void testDsaPublicKeyLength() {
        DsaPublicKey publicKey = new DsaPublicKey(Q, Y, G, P);
        assertEquals(P.bitLength(), publicKey.length());
    }

    @Test
    void testDsaPublicKeyAlgorithmType() {
        DsaPublicKey publicKey = new DsaPublicKey(Q, Y, G, P);
        assertEquals(AsymmetricAlgorithmType.DSA, publicKey.getAlgorithmType());
    }

    @Test
    void testDsaPublicKeyEqualsAndHashCode() {
        DsaPublicKey publicKey1 = new DsaPublicKey(Q, Y, G, P);
        DsaPublicKey publicKey2 = new DsaPublicKey(Q, Y, G, P);
        DsaPublicKey differentQ = new DsaPublicKey(Q.add(BigInteger.ONE), Y, G, P);
        DsaPublicKey differentY = new DsaPublicKey(Q, Y.add(BigInteger.ONE), G, P);
        DsaPublicKey differentG = new DsaPublicKey(Q, Y, G.add(BigInteger.ONE), P);
        DsaPublicKey differentP = new DsaPublicKey(Q, Y, G, P.add(BigInteger.ONE));

        // Test equals
        assertTrue(publicKey1.equals(publicKey1)); // Same object
        assertTrue(publicKey1.equals(publicKey2)); // Equal objects
        assertFalse(publicKey1.equals(null)); // Null comparison
        assertFalse(publicKey1.equals(new Object())); // Different class
        assertFalse(publicKey1.equals(differentQ)); // Different Q
        assertFalse(publicKey1.equals(differentY)); // Different Y
        assertFalse(publicKey1.equals(differentG)); // Different G
        assertFalse(publicKey1.equals(differentP)); // Different P

        // Test hashCode
        assertEquals(publicKey1.hashCode(), publicKey2.hashCode());
    }
}
