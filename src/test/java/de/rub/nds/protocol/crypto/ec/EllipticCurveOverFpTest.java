/*
 * Protocol-Attacker - A Framework to create Protocol Analysis Tools
 *
 * Copyright 2023-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.protocol.crypto.ec;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import org.junit.jupiter.api.Test;

/** Test for EllipticCurveOverFp to ensure correct point validation */
class EllipticCurveOverFpTest {

    /**
     * Test that isOnCurve correctly compares modulus values, not references. This test verifies the
     * fix for issue #1 where modulus comparison was done by reference instead of by value.
     */
    @Test
    void testIsOnCurveWithDifferentModulusReferences() {
        // Create a simple elliptic curve: y^2 = x^3 + ax + b (mod p)
        // Using the curve y^2 = x^3 + 2x + 3 (mod 17)
        BigInteger p = new BigInteger("17");
        BigInteger a = new BigInteger("2");
        BigInteger b = new BigInteger("3");

        EllipticCurveOverFp curve = new EllipticCurveOverFp(a, b, p);

        // Create a point that is on the curve: (2, 10)
        // Verify: 10^2 = 2^3 + 2*2 + 3 (mod 17)
        // 100 = 8 + 4 + 3 (mod 17)
        // 100 mod 17 = 15, and 15 mod 17 = 15 ✓
        BigInteger x = new BigInteger("2");
        BigInteger y = new BigInteger("10");

        // Create field elements with the same modulus value but different object references
        FieldElementFp fieldX = new FieldElementFp(x, new BigInteger("17"));
        FieldElementFp fieldY = new FieldElementFp(y, new BigInteger("17"));
        Point pointOnCurve = new Point(fieldX, fieldY);

        // This should return true since the point is on the curve
        assertTrue(
                curve.isOnCurve(pointOnCurve),
                "Point (2, 10) should be on curve y^2 = x^3 + 2x + 3 (mod 17)");

        // Test with a point not on the curve: (2, 2)
        FieldElementFp fieldY2 = new FieldElementFp(new BigInteger("2"), new BigInteger("17"));
        Point pointNotOnCurve = new Point(fieldX, fieldY2);

        assertFalse(
                curve.isOnCurve(pointNotOnCurve),
                "Point (2, 2) should not be on curve y^2 = x^3 + 2x + 3 (mod 17)");

        // Test with different modulus - point should not be on curve
        FieldElementFp fieldXDifferentMod = new FieldElementFp(x, new BigInteger("19"));
        FieldElementFp fieldYDifferentMod = new FieldElementFp(y, new BigInteger("19"));
        Point pointDifferentMod = new Point(fieldXDifferentMod, fieldYDifferentMod);

        assertFalse(
                curve.isOnCurve(pointDifferentMod),
                "Point with different modulus should not be considered on the curve");
    }

    /** Test that the infinity point is correctly identified as being on the curve */
    @Test
    void testInfinityPointOnCurve() {
        BigInteger p = new BigInteger("17");
        BigInteger a = new BigInteger("2");
        BigInteger b = new BigInteger("3");

        EllipticCurveOverFp curve = new EllipticCurveOverFp(a, b, p);
        Point infinity = new Point();

        assertTrue(curve.isOnCurve(infinity), "The point at infinity should be on the curve");
    }
}
