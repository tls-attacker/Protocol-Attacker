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
import static org.junit.jupiter.api.Assertions.assertNull;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

public class MacAlgorithmTest {

    @Test
    public void testNoneAlgorithm() {
        MacAlgorithm algorithm = MacAlgorithm.NONE;
        assertEquals(0, algorithm.getMacLength());
        assertEquals(0, algorithm.getKeySize());
        assertNull(algorithm.getJavaName());
    }

    @ParameterizedTest
    @CsvSource({
        "HMAC_MD5, 16, 16, HmacMD5",
        "HMAC_SHA1, 20, 20, HmacSHA1",
        "HMAC_SHA256, 32, 32, HmacSHA256",
        "HMAC_SHA384, 48, 48, HmacSHA384",
        "HMAC_SHA512, 64, 64, HmacSHA512",
        "HMAC_SHA512_224, 28, 28, HmacSHA512/224",
        "HMAC_SHA512_256, 32, 32, HmacSHA512/256"
    })
    public void testStandardHmacAlgorithms(
            String algorithmName, int macLength, int keySize, String javaName) {
        MacAlgorithm algorithm = MacAlgorithm.valueOf(algorithmName);
        assertEquals(macLength, algorithm.getMacLength());
        assertEquals(keySize, algorithm.getKeySize());
        assertEquals(javaName, algorithm.getJavaName());
    }

    @Test
    public void testSslMacMD5() {
        MacAlgorithm algorithm = MacAlgorithm.SSLMAC_MD5;
        assertEquals(16, algorithm.getMacLength());
        assertEquals(16, algorithm.getKeySize());
        assertEquals("SslMacMD5", algorithm.getJavaName());
    }

    @Test
    public void testSslMacSHA1() {
        MacAlgorithm algorithm = MacAlgorithm.SSLMAC_SHA1;
        assertEquals(20, algorithm.getMacLength());
        assertEquals(20, algorithm.getKeySize());
        assertEquals("SslMacSHA1", algorithm.getJavaName());
    }

    @Test
    public void testImitGost28147() {
        MacAlgorithm algorithm = MacAlgorithm.IMIT_GOST28147;
        assertEquals(4, algorithm.getMacLength());
        assertEquals(32, algorithm.getKeySize());
        assertEquals("GOST28147MAC", algorithm.getJavaName());
    }

    @Test
    public void testHmacGostR3411() {
        MacAlgorithm algorithm = MacAlgorithm.HMAC_GOSTR3411;
        assertEquals(32, algorithm.getMacLength());
        assertEquals(32, algorithm.getKeySize());
        assertEquals("HmacGOST3411", algorithm.getJavaName());
    }

    @Test
    public void testHmacGostR3411_2012_256() {
        MacAlgorithm algorithm = MacAlgorithm.HMAC_GOSTR3411_2012_256;
        assertEquals(32, algorithm.getMacLength());
        assertEquals(32, algorithm.getKeySize());
        assertEquals("HmacGOST3411-2012-256", algorithm.getJavaName());
    }

    @Test
    public void testHmacSM3() {
        MacAlgorithm algorithm = MacAlgorithm.HMAC_SM3;
        assertEquals(32, algorithm.getMacLength());
        assertEquals(32, algorithm.getKeySize());
        assertEquals("HmacSM3", algorithm.getJavaName());
    }
}
