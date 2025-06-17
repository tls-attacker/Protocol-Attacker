/*
 * Protocol-Attacker - A Framework to create Protocol Analysis Tools
 *
 * Copyright 2023-2024 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.protocol.constants;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.rub.nds.protocol.crypto.ec.EllipticCurve;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

class NamedEllipticCurveParametersTest {

    @Test
    void testImplementsGroupParameters() {
        // Test that NamedEllipticCurveParameters implements GroupParameters
        NamedEllipticCurveParameters curve = NamedEllipticCurveParameters.SECP256R1;
        assertTrue(curve instanceof GroupParameters);

        // Test the element size methods
        assertEquals(256, curve.getElementSizeBits());
        assertEquals(32, curve.getElementSizeBytes());

        // Test that getGroup returns an EllipticCurve
        assertTrue(curve.getGroup() instanceof EllipticCurve);
    }

    @Test
    void testCurveNames() {
        // Test specific curve names
        assertEquals("secp256r1", NamedEllipticCurveParameters.SECP256R1.getName());
        assertEquals("prime256v1", NamedEllipticCurveParameters.SECP256R1.getX962name());
        assertEquals("NIST P-256", NamedEllipticCurveParameters.SECP256R1.getNistName());
        assertEquals("secp256r1", NamedEllipticCurveParameters.SECP256R1.getSecName());

        // Test Montgomery curve
        assertEquals("CurveX25519", NamedEllipticCurveParameters.CURVE_X25519.getName());
        assertEquals(
                EcCurveEquationType.MONTGOMERY,
                NamedEllipticCurveParameters.CURVE_X25519.getEquationType());
    }

    @ParameterizedTest
    @EnumSource(NamedEllipticCurveParameters.class)
    void testAllCurvesHaveNames(NamedEllipticCurveParameters curve) {
        // Every curve should have a name
        assertNotNull(curve.getName());
        assertNotNull(curve.getEquationType());
        assertTrue(curve.getElementSizeBits() > 0);
        assertTrue(curve.getElementSizeBytes() > 0);
        assertNotNull(curve.getGroup());
    }

    @Test
    void testElementSizeCalculation() {
        // Test the element size calculation for various bit lengths
        assertEquals(
                14,
                NamedEllipticCurveParameters.SECP112R1
                        .getElementSizeBytes()); // 112 bits -> 14 bytes
        assertEquals(
                24,
                NamedEllipticCurveParameters.SECP192R1
                        .getElementSizeBytes()); // 192 bits -> 24 bytes
        assertEquals(
                32,
                NamedEllipticCurveParameters.SECP256R1
                        .getElementSizeBytes()); // 256 bits -> 32 bytes
        assertEquals(
                48,
                NamedEllipticCurveParameters.SECP384R1
                        .getElementSizeBytes()); // 384 bits -> 48 bytes
        assertEquals(
                66,
                NamedEllipticCurveParameters.SECP521R1
                        .getElementSizeBytes()); // 521 bits -> 66 bytes
    }

    @Test
    void testCurveTypes() {
        // Test different curve equation types
        assertEquals(
                EcCurveEquationType.SHORT_WEIERSTRASS,
                NamedEllipticCurveParameters.SECP256R1.getEquationType());
        assertEquals(
                EcCurveEquationType.MONTGOMERY,
                NamedEllipticCurveParameters.CURVE_X25519.getEquationType());

        // Test that no curve has EDWARDS type yet (as of the current implementation)
        boolean hasEdwardsCurve = false;
        for (NamedEllipticCurveParameters curve : NamedEllipticCurveParameters.values()) {
            if (curve.getEquationType() == EcCurveEquationType.EDWARDS) {
                hasEdwardsCurve = true;
                break;
            }
        }
        // This test might need to be updated if Edwards curves are added
        assertEquals(false, hasEdwardsCurve);
    }
}
