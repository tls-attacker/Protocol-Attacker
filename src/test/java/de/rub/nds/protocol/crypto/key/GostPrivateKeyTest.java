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
import static org.junit.jupiter.api.Assertions.assertNotNull;

import de.rub.nds.protocol.constants.NamedEllipticCurveParameters;
import java.math.BigInteger;
import org.junit.jupiter.api.Test;

/** Test class for GOST private key. */
class GostPrivateKeyTest {

    @Test
    void testGostPrivateKeyCreation() {
        BigInteger privateKey = new BigInteger("12345678901234567890");
        BigInteger nonce = new BigInteger("98765432109876543210");
        NamedEllipticCurveParameters parameters = NamedEllipticCurveParameters.GOST2001_SETA;

        GostPrivateKey gostKey = new GostPrivateKey(privateKey, nonce, parameters);

        assertNotNull(gostKey);
        assertEquals(privateKey, gostKey.getPrivateKey());
        assertEquals(nonce, gostKey.getNonce());
        assertEquals(parameters, gostKey.getParameters());
    }

    @Test
    void testGostPrivateKeyWithGost2012Parameters() {
        BigInteger privateKey =
                new BigInteger(
                        "115792089237316195423570985008687907853269984665640564039457584007913129639319");
        BigInteger nonce =
                new BigInteger(
                        "115792089237316195423570985008687907853269984665640564039457584007913129639318");
        NamedEllipticCurveParameters parameters = NamedEllipticCurveParameters.GOST2012_SETA256;

        GostPrivateKey gostKey = new GostPrivateKey(privateKey, nonce, parameters);

        assertNotNull(gostKey);
        assertEquals(privateKey, gostKey.getPrivateKey());
        assertEquals(nonce, gostKey.getNonce());
        assertEquals(parameters, gostKey.getParameters());
    }

    @Test
    void testGostPrivateKeyWithGost2012_512Parameters() {
        BigInteger privateKey = BigInteger.valueOf(Long.MAX_VALUE);
        BigInteger nonce = BigInteger.valueOf(Long.MAX_VALUE - 1);
        NamedEllipticCurveParameters parameters = NamedEllipticCurveParameters.GOST2012_SETA512;

        GostPrivateKey gostKey = new GostPrivateKey(privateKey, nonce, parameters);

        assertNotNull(gostKey);
        assertEquals(privateKey, gostKey.getPrivateKey());
        assertEquals(nonce, gostKey.getNonce());
        assertEquals(parameters, gostKey.getParameters());
    }

    @Test
    void testGostPrivateKeyWithAllGostCurves() {
        BigInteger privateKey = BigInteger.valueOf(999999);
        BigInteger nonce = BigInteger.valueOf(888888);

        // Test with all GOST curves
        NamedEllipticCurveParameters[] gostCurves = {
            NamedEllipticCurveParameters.GOST2001_SETA,
            NamedEllipticCurveParameters.GOST2001_SETB,
            NamedEllipticCurveParameters.GOST2001_SETC,
            NamedEllipticCurveParameters.GOST2001_SETXCHA,
            NamedEllipticCurveParameters.GOST2001_SETXCHB,
            NamedEllipticCurveParameters.GOST2012_SETA256,
            NamedEllipticCurveParameters.GOST2012_SETA512,
            NamedEllipticCurveParameters.GOST2012_SETB512,
            NamedEllipticCurveParameters.GOST2012_SETC512
        };

        for (NamedEllipticCurveParameters curve : gostCurves) {
            GostPrivateKey gostKey = new GostPrivateKey(privateKey, nonce, curve);
            assertNotNull(gostKey);
            assertEquals(privateKey, gostKey.getPrivateKey());
            assertEquals(nonce, gostKey.getNonce());
            assertEquals(curve, gostKey.getParameters());
        }
    }
}
