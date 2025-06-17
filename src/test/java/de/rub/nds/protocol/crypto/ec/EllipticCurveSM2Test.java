/*
 * Protocol-Attacker - A Framework to create Protocol Analysis Tools
 *
 * Copyright 2023-2024 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.protocol.crypto.ec;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class EllipticCurveSM2Test {

    private EllipticCurveSM2 curve;

    @BeforeEach
    void setUp() {
        curve = new EllipticCurveSM2();
    }

    @Test
    void testCurveParameters() {
        // Verify the curve parameters match the SM2 specification

        // A coefficient
        assertEquals(
                new BigInteger(
                        "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC", 16),
                curve.getFieldA().getData());

        // B coefficient
        assertEquals(
                new BigInteger(
                        "28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93", 16),
                curve.getFieldB().getData());

        // Prime modulus
        assertEquals(
                new BigInteger(
                        "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF", 16),
                curve.getModulus());

        // Base point X coordinate
        assertEquals(
                new BigInteger(
                        "32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7", 16),
                curve.getBasePoint().getFieldX().getData());

        // Base point Y coordinate
        assertEquals(
                new BigInteger(
                        "BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0", 16),
                curve.getBasePoint().getFieldY().getData());

        // Base point order
        assertEquals(
                new BigInteger(
                        "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123", 16),
                curve.getBasePointOrder());
    }

    @Test
    void testBasePointIsOnCurve() {
        // Verify that the base point is actually on the curve
        assertTrue(curve.isOnCurve(curve.getBasePoint()));
    }

    @Test
    void testPointMultiplication() {
        // Test scalar multiplication with a small scalar
        Point basePoint = curve.getBasePoint();
        BigInteger scalar = new BigInteger("3");

        // 3 * basePoint
        Point resultPoint = curve.mult(scalar, basePoint);

        // Verify the result is not null and is on the curve
        assertNotNull(resultPoint);
        assertTrue(curve.isOnCurve(resultPoint));

        // Alternative calculation: basePoint + basePoint + basePoint
        Point expected = curve.add(curve.add(basePoint, basePoint), basePoint);

        // Verify the results match
        assertEquals(expected.getFieldX().getData(), resultPoint.getFieldX().getData());
        assertEquals(expected.getFieldY().getData(), resultPoint.getFieldY().getData());
    }
}
