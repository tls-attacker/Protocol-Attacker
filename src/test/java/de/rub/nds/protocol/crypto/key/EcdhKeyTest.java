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
import de.rub.nds.protocol.constants.NamedEllipticCurveParameters;
import de.rub.nds.protocol.crypto.ec.Point;
import java.math.BigInteger;
import java.util.Random;
import org.junit.jupiter.api.Test;

class EcdhKeyTest {

    private static final Random RANDOM = new Random(42); // Fixed seed for reproducibility
    private static final BigInteger PRIVATE_KEY = new BigInteger("123456789", 10);
    private static final NamedEllipticCurveParameters CURVE_PARAMS =
            NamedEllipticCurveParameters.SECP256R1;

    @Test
    void testEcdhPrivateKey() {
        EcdhPrivateKey privateKey = new EcdhPrivateKey(PRIVATE_KEY, CURVE_PARAMS);

        assertEquals(PRIVATE_KEY, privateKey.getPrivateKey());
        assertEquals(CURVE_PARAMS, privateKey.getParameters());
    }

    @Test
    void testEcdhPublicKeyConstruction() {
        // Generate a valid point on the curve for testing
        Point publicPoint = CURVE_PARAMS.getGroup().nTimesGroupOperationOnGenerator(PRIVATE_KEY);
        EcdhPublicKey publicKey = new EcdhPublicKey(publicPoint, CURVE_PARAMS);

        assertEquals(publicPoint, publicKey.getPublicPoint());
        assertEquals(CURVE_PARAMS, publicKey.getParameters());
    }

    @Test
    void testEcdhPublicKeySetters() {
        Point publicPoint = CURVE_PARAMS.getGroup().nTimesGroupOperationOnGenerator(PRIVATE_KEY);
        EcdhPublicKey publicKey = new EcdhPublicKey(publicPoint, CURVE_PARAMS);

        // Create a different point and parameters for testing setters
        Point newPoint =
                CURVE_PARAMS
                        .getGroup()
                        .nTimesGroupOperationOnGenerator(PRIVATE_KEY.add(BigInteger.ONE));
        NamedEllipticCurveParameters newParams = NamedEllipticCurveParameters.SECP384R1;

        publicKey.setPublicPoint(newPoint);
        publicKey.setParameters(newParams);

        assertEquals(newPoint, publicKey.getPublicPoint());
        assertEquals(newParams, publicKey.getParameters());
    }

    @Test
    void testEcdhPublicKeyLength() {
        Point publicPoint = CURVE_PARAMS.getGroup().nTimesGroupOperationOnGenerator(PRIVATE_KEY);
        EcdhPublicKey publicKey = new EcdhPublicKey(publicPoint, CURVE_PARAMS);

        assertEquals(CURVE_PARAMS.getElementSizeBits(), publicKey.length());
    }

    @Test
    void testEcdhPublicKeyAlgorithmType() {
        Point publicPoint = CURVE_PARAMS.getGroup().nTimesGroupOperationOnGenerator(PRIVATE_KEY);
        EcdhPublicKey publicKey = new EcdhPublicKey(publicPoint, CURVE_PARAMS);

        assertEquals(AsymmetricAlgorithmType.ECDH, publicKey.getAlgorithmType());
    }

    @Test
    void testEcdhPublicKeyEqualsAndHashCode() {
        Point publicPoint = CURVE_PARAMS.getGroup().nTimesGroupOperationOnGenerator(PRIVATE_KEY);
        EcdhPublicKey publicKey1 = new EcdhPublicKey(publicPoint, CURVE_PARAMS);
        EcdhPublicKey publicKey2 = new EcdhPublicKey(publicPoint, CURVE_PARAMS);

        Point differentPoint =
                CURVE_PARAMS
                        .getGroup()
                        .nTimesGroupOperationOnGenerator(PRIVATE_KEY.add(BigInteger.ONE));
        EcdhPublicKey differentPointKey = new EcdhPublicKey(differentPoint, CURVE_PARAMS);

        NamedEllipticCurveParameters differentCurve = NamedEllipticCurveParameters.SECP384R1;
        Point pointOnDifferentCurve =
                differentCurve.getGroup().nTimesGroupOperationOnGenerator(PRIVATE_KEY);
        EcdhPublicKey differentCurveKey = new EcdhPublicKey(pointOnDifferentCurve, differentCurve);

        // Test equals
        assertTrue(publicKey1.equals(publicKey1)); // Same object
        assertTrue(publicKey1.equals(publicKey2)); // Equal objects
        assertFalse(publicKey1.equals(null)); // Null comparison
        assertFalse(publicKey1.equals(new Object())); // Different class
        assertFalse(publicKey1.equals(differentPointKey)); // Different point
        assertFalse(publicKey1.equals(differentCurveKey)); // Different curve

        // Test hashCode
        assertEquals(publicKey1.hashCode(), publicKey2.hashCode());
    }

    @Test
    void testEcdhKeyGeneration() {
        BigInteger privateKey = new BigInteger(256, RANDOM);

        // Test with SECP256R1 curve
        EcdhPublicKey publicKey = KeyGenerator.generateEcdhPublicKey(privateKey, CURVE_PARAMS);

        assertNotNull(publicKey);
        assertEquals(CURVE_PARAMS, publicKey.getParameters());

        // Verify the public key is calculated correctly
        Point expectedPoint = CURVE_PARAMS.getGroup().nTimesGroupOperationOnGenerator(privateKey);
        assertEquals(expectedPoint, publicKey.getPublicPoint());

        // Verify the point is valid
        assertTrue(publicKey.getPublicPoint() != null);
        assertTrue(publicKey.getPublicPoint().getFieldX() != null);
        assertTrue(publicKey.getPublicPoint().getFieldY() != null);
    }

    @Test
    void testEcdhKeyExchange() {
        // Create Alice's key pair
        BigInteger alicePrivateKey = new BigInteger(256, RANDOM);
        EcdhPrivateKey alicePrivate = new EcdhPrivateKey(alicePrivateKey, CURVE_PARAMS);
        EcdhPublicKey alicePublic =
                KeyGenerator.generateEcdhPublicKey(alicePrivateKey, CURVE_PARAMS);

        // Create Bob's key pair
        BigInteger bobPrivateKey = new BigInteger(256, RANDOM);
        EcdhPrivateKey bobPrivate = new EcdhPrivateKey(bobPrivateKey, CURVE_PARAMS);
        EcdhPublicKey bobPublic = KeyGenerator.generateEcdhPublicKey(bobPrivateKey, CURVE_PARAMS);

        // Simulate key exchange - Alice computes shared secret using Bob's public key
        Point aliceSharedSecret =
                CURVE_PARAMS
                        .getGroup()
                        .nTimesGroupOperation(bobPublic.getPublicPoint(), alicePrivateKey);

        // Bob computes shared secret using Alice's public key
        Point bobSharedSecret =
                CURVE_PARAMS
                        .getGroup()
                        .nTimesGroupOperation(alicePublic.getPublicPoint(), bobPrivateKey);

        // Verify both computed the same shared secret
        assertEquals(aliceSharedSecret, bobSharedSecret);
    }
}
