/*
 * Protocol-Attacker - A Framework to create Protocol Analysis Tools
 *
 * Copyright 2023-2024 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.protocol.crypto.hash;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import de.rub.nds.protocol.constants.HashAlgorithm;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.EnumSource.Mode;

class HashCalculatorTest {

    private static final byte[] TEST_DATA =
            "Protocol-Attacker test data".getBytes(StandardCharsets.UTF_8);

    @BeforeAll
    static void setup() {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    void testHashWithNoneAlgorithm() {
        // Arrange
        HashAlgorithm algorithm = HashAlgorithm.NONE;

        // Act
        byte[] result = HashCalculator.compute(TEST_DATA, algorithm);

        // Assert
        assertArrayEquals(
                TEST_DATA,
                result,
                "When using NONE algorithm, the original data should be returned");
    }

    @ParameterizedTest
    @EnumSource(
            value = HashAlgorithm.class,
            mode = Mode.INCLUDE,
            names = {"SHA1", "SHA256", "SHA384", "SHA512"})
    void testHashWithStandardAlgorithms(HashAlgorithm algorithm) throws NoSuchAlgorithmException {
        // Skip if no Java implementation available
        if (algorithm.getJavaName() == null) {
            return;
        }

        // Arrange - compute expected result using Java's MessageDigest
        MessageDigest digest = MessageDigest.getInstance(algorithm.getJavaName());
        byte[] expected = digest.digest(TEST_DATA);

        // Act
        byte[] result = HashCalculator.compute(TEST_DATA, algorithm);

        // Assert
        assertArrayEquals(
                expected,
                result,
                "Hash result should match Java's MessageDigest result for " + algorithm);
        assertEquals(
                algorithm.getBitLength() / 8,
                result.length,
                "Hash output length should match expected bit length");
    }

    @Test
    void testHashWithEmptyInput() throws NoSuchAlgorithmException {
        // Arrange
        byte[] emptyData = new byte[0];
        HashAlgorithm algorithm = HashAlgorithm.SHA256;

        // Compute expected result
        MessageDigest digest = MessageDigest.getInstance(algorithm.getJavaName());
        byte[] expected = digest.digest(emptyData);

        // Act
        byte[] result = HashCalculator.compute(emptyData, algorithm);

        // Assert
        assertArrayEquals(expected, result, "Should be able to hash empty byte array");
    }

    @Test
    void testGostR3411_94Algorithm() throws NoSuchAlgorithmException, NoSuchProviderException {
        // Arrange
        HashAlgorithm algorithm = HashAlgorithm.GOST_R3411_94;

        // Act
        byte[] result = HashCalculator.compute(TEST_DATA, algorithm);

        // Assert
        assertNotNull(result, "GOST R 34.11-94 should produce a result");
        assertEquals(
                algorithm.getBitLength() / 8,
                result.length,
                "GOST R 34.11-94 output length should match expected bit length");
        assertEquals(32, result.length, "GOST R 34.11-94 should produce 32 bytes");

        // Verify using BouncyCastle's MessageDigest
        MessageDigest digest = MessageDigest.getInstance(algorithm.getJavaName(), "BC");
        byte[] expected = digest.digest(TEST_DATA);
        assertArrayEquals(
                expected, result, "Hash result should match BouncyCastle's GOST R 34.11-94 result");
    }

    @Test
    void testGostR3411_12Algorithm() throws NoSuchAlgorithmException, NoSuchProviderException {
        // Arrange
        HashAlgorithm algorithm = HashAlgorithm.GOST_R3411_12;

        // Act
        byte[] result = HashCalculator.compute(TEST_DATA, algorithm);

        // Assert
        assertNotNull(result, "GOST R 34.11-2012 should produce a result");
        assertEquals(
                algorithm.getBitLength() / 8,
                result.length,
                "GOST R 34.11-2012 output length should match expected bit length");
        assertEquals(32, result.length, "GOST R 34.11-2012 (256-bit) should produce 32 bytes");

        // Verify using BouncyCastle's MessageDigest
        MessageDigest digest = MessageDigest.getInstance(algorithm.getJavaName(), "BC");
        byte[] expected = digest.digest(TEST_DATA);
        assertArrayEquals(
                expected,
                result,
                "Hash result should match BouncyCastle's GOST R 34.11-2012 result");
    }

    @ParameterizedTest
    @EnumSource(
            value = HashAlgorithm.class,
            mode = Mode.INCLUDE,
            names = {"GOST_R3411_94", "GOST_R3411_12"})
    void testGostAlgorithmsWithVariousInputs(HashAlgorithm algorithm)
            throws NoSuchAlgorithmException, NoSuchProviderException {
        // Test with different input sizes
        byte[][] testInputs = {
            new byte[0], // Empty input
            "A".getBytes(StandardCharsets.UTF_8), // Single byte
            "Test".getBytes(StandardCharsets.UTF_8), // Small input
            TEST_DATA, // Standard test data
            new byte[1024] // Large input (filled with zeros)
        };

        for (byte[] input : testInputs) {
            // Act
            byte[] result = HashCalculator.compute(input, algorithm);

            // Assert
            assertNotNull(
                    result, algorithm + " should produce a result for input size " + input.length);
            assertEquals(
                    32,
                    result.length,
                    algorithm + " should always produce 32 bytes for input size " + input.length);

            // Verify with BouncyCastle
            MessageDigest digest = MessageDigest.getInstance(algorithm.getJavaName(), "BC");
            byte[] expected = digest.digest(input);
            assertArrayEquals(
                    expected,
                    result,
                    algorithm + " result should match BouncyCastle for input size " + input.length);
        }
    }

    @Test
    void testGostAlgorithmsInParameterizedTest() throws NoSuchAlgorithmException {
        // This test verifies that GOST algorithms work in the existing parameterized test framework
        HashAlgorithm[] gostAlgorithms = {HashAlgorithm.GOST_R3411_94, HashAlgorithm.GOST_R3411_12};

        for (HashAlgorithm algorithm : gostAlgorithms) {
            // Act
            byte[] result = HashCalculator.compute(TEST_DATA, algorithm);

            // Assert
            assertNotNull(result, algorithm + " should produce a result");
            assertEquals(
                    algorithm.getBitLength() / 8,
                    result.length,
                    algorithm + " output length should match expected bit length");
        }
    }
}
