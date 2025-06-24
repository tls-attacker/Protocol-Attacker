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

class EddsaKeyTest {

    private static final Random RANDOM = new Random(42); // Fixed seed for reproducibility
    private static final BigInteger PRIVATE_KEY = new BigInteger("123456789", 10);
    private static final NamedEllipticCurveParameters CURVE_PARAMS =
            NamedEllipticCurveParameters.CURVE_X25519;

    @Test
    void testEddsaPrivateKey() {
        EddsaPrivateKey privateKey = new EddsaPrivateKey(PRIVATE_KEY, CURVE_PARAMS);

        assertEquals(PRIVATE_KEY, privateKey.getPrivateKey());
        assertEquals(CURVE_PARAMS, privateKey.getParameters());
    }

    @Test
    void testEddsaPublicKeyConstruction() {
        // Generate a valid point on the curve for testing
        Point publicPoint = CURVE_PARAMS.getGroup().nTimesGroupOperationOnGenerator(PRIVATE_KEY);
        EddsaPublicKey publicKey = new EddsaPublicKey(publicPoint, CURVE_PARAMS);

        assertEquals(publicPoint, publicKey.getPublicPoint());
        assertEquals(CURVE_PARAMS, publicKey.getParameters());
    }

    @Test
    void testEddsaPublicKeySetters() {
        Point publicPoint = CURVE_PARAMS.getGroup().nTimesGroupOperationOnGenerator(PRIVATE_KEY);
        EddsaPublicKey publicKey = new EddsaPublicKey(publicPoint, CURVE_PARAMS);

        // Create a different point and parameters for testing setters
        Point newPoint =
                CURVE_PARAMS
                        .getGroup()
                        .nTimesGroupOperationOnGenerator(PRIVATE_KEY.add(BigInteger.ONE));
        NamedEllipticCurveParameters newParams = NamedEllipticCurveParameters.CURVE_X448;

        publicKey.setPublicPoint(newPoint);
        publicKey.setParameters(newParams);

        assertEquals(newPoint, publicKey.getPublicPoint());
        assertEquals(newParams, publicKey.getParameters());
    }

    @Test
    void testEddsaPublicKeyLength() {
        Point publicPoint = CURVE_PARAMS.getGroup().nTimesGroupOperationOnGenerator(PRIVATE_KEY);
        EddsaPublicKey publicKey = new EddsaPublicKey(publicPoint, CURVE_PARAMS);

        assertEquals(CURVE_PARAMS.getElementSizeBits(), publicKey.length());
    }

    @Test
    void testEddsaPublicKeyAlgorithmType() {
        Point publicPoint = CURVE_PARAMS.getGroup().nTimesGroupOperationOnGenerator(PRIVATE_KEY);
        EddsaPublicKey publicKey = new EddsaPublicKey(publicPoint, CURVE_PARAMS);

        assertEquals(AsymmetricAlgorithmType.EDDSA, publicKey.getAlgorithmType());
    }

    @Test
    void testEddsaPublicKeyEqualsAndHashCode() {
        Point publicPoint = CURVE_PARAMS.getGroup().nTimesGroupOperationOnGenerator(PRIVATE_KEY);
        EddsaPublicKey publicKey1 = new EddsaPublicKey(publicPoint, CURVE_PARAMS);
        EddsaPublicKey publicKey2 = new EddsaPublicKey(publicPoint, CURVE_PARAMS);

        Point differentPoint =
                CURVE_PARAMS
                        .getGroup()
                        .nTimesGroupOperationOnGenerator(PRIVATE_KEY.add(BigInteger.ONE));
        EddsaPublicKey differentPointKey = new EddsaPublicKey(differentPoint, CURVE_PARAMS);

        NamedEllipticCurveParameters differentCurve = NamedEllipticCurveParameters.CURVE_X448;
        Point pointOnDifferentCurve =
                differentCurve.getGroup().nTimesGroupOperationOnGenerator(PRIVATE_KEY);
        EddsaPublicKey differentCurveKey =
                new EddsaPublicKey(pointOnDifferentCurve, differentCurve);

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
    void testEddsaKeyGeneration() {
        BigInteger privateKey = new BigInteger(255, RANDOM);

        // Test with Curve25519
        EddsaPublicKey publicKey = KeyGenerator.generateEddsaPublicKey(privateKey, CURVE_PARAMS);

        assertNotNull(publicKey);
        assertEquals(CURVE_PARAMS, publicKey.getParameters());

        // Verify the public key is calculated correctly
        Point expectedPoint = CURVE_PARAMS.getGroup().nTimesGroupOperationOnGenerator(privateKey);
        assertEquals(expectedPoint, publicKey.getPublicPoint());

        // For Edwards curves like Curve25519, verify the point is valid
        assertTrue(publicKey.getPublicPoint() != null);
        assertTrue(publicKey.getPublicPoint().getFieldX() != null);
        assertTrue(publicKey.getPublicPoint().getFieldY() != null);
    }
}
