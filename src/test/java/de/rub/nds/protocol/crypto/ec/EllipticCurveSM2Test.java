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
