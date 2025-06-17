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

public class EcdsaKeyTest {

    private static final Random RANDOM = new Random(42); // Fixed seed for reproducibility
    private static final BigInteger PRIVATE_KEY = new BigInteger("123456789", 10);
    private static final BigInteger NONCE = new BigInteger("987654321", 10);
    private static final NamedEllipticCurveParameters CURVE_PARAMS =
            NamedEllipticCurveParameters.SECP256R1;

    @Test
    public void testEcdsaPrivateKey() {
        EcdsaPrivateKey privateKey = new EcdsaPrivateKey(PRIVATE_KEY, NONCE, CURVE_PARAMS);

        assertEquals(PRIVATE_KEY, privateKey.getPrivateKey());
        assertEquals(NONCE, privateKey.getNonce());
        assertEquals(CURVE_PARAMS, privateKey.getParameters());
    }

    @Test
    public void testEcdsaPublicKeyConstruction() {
        // Generate a valid point on the curve for testing
        Point publicPoint = CURVE_PARAMS.getGroup().nTimesGroupOperationOnGenerator(PRIVATE_KEY);
        EcdsaPublicKey publicKey = new EcdsaPublicKey(publicPoint, CURVE_PARAMS);

        assertEquals(publicPoint, publicKey.getPublicPoint());
        assertEquals(CURVE_PARAMS, publicKey.getParameters());
    }

    @Test
    public void testEcdsaPublicKeySetters() {
        Point publicPoint = CURVE_PARAMS.getGroup().nTimesGroupOperationOnGenerator(PRIVATE_KEY);
        EcdsaPublicKey publicKey = new EcdsaPublicKey(publicPoint, CURVE_PARAMS);

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
    public void testEcdsaPublicKeyLength() {
        Point publicPoint = CURVE_PARAMS.getGroup().nTimesGroupOperationOnGenerator(PRIVATE_KEY);
        EcdsaPublicKey publicKey = new EcdsaPublicKey(publicPoint, CURVE_PARAMS);

        assertEquals(CURVE_PARAMS.getElementSizeBits(), publicKey.length());
    }

    @Test
    public void testEcdsaPublicKeyAlgorithmType() {
        Point publicPoint = CURVE_PARAMS.getGroup().nTimesGroupOperationOnGenerator(PRIVATE_KEY);
        EcdsaPublicKey publicKey = new EcdsaPublicKey(publicPoint, CURVE_PARAMS);

        assertEquals(AsymmetricAlgorithmType.ECDSA, publicKey.getAlgorithmType());
    }

    @Test
    public void testEcdsaPublicKeyEqualsAndHashCode() {
        Point publicPoint = CURVE_PARAMS.getGroup().nTimesGroupOperationOnGenerator(PRIVATE_KEY);
        EcdsaPublicKey publicKey1 = new EcdsaPublicKey(publicPoint, CURVE_PARAMS);
        EcdsaPublicKey publicKey2 = new EcdsaPublicKey(publicPoint, CURVE_PARAMS);

        Point differentPoint =
                CURVE_PARAMS
                        .getGroup()
                        .nTimesGroupOperationOnGenerator(PRIVATE_KEY.add(BigInteger.ONE));
        EcdsaPublicKey differentPointKey = new EcdsaPublicKey(differentPoint, CURVE_PARAMS);

        NamedEllipticCurveParameters differentCurve = NamedEllipticCurveParameters.SECP384R1;
        Point pointOnDifferentCurve =
                differentCurve.getGroup().nTimesGroupOperationOnGenerator(PRIVATE_KEY);
        EcdsaPublicKey differentCurveKey =
                new EcdsaPublicKey(pointOnDifferentCurve, differentCurve);

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
    public void testEcdsaKeyGeneration() {
        BigInteger privateKey = new BigInteger(256, RANDOM);

        // Test with SECP256R1 curve
        EcdsaPublicKey publicKey = KeyGenerator.generateEcdsaPublicKey(privateKey, CURVE_PARAMS);

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
}
