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
import static org.junit.jupiter.api.Assertions.assertThrows;

import de.rub.nds.protocol.constants.HashAlgorithm;
import de.rub.nds.protocol.exception.CryptoException;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
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

    @ParameterizedTest
    @EnumSource(
            value = HashAlgorithm.class,
            mode = Mode.INCLUDE,
            names = {"GOST_R3411_94", "GOST_R3411_12"})
    void testHashWithGostAlgorithms(HashAlgorithm algorithm)
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
    void testPrivateConstructor() throws Exception {
        // Arrange
        Constructor<HashCalculator> constructor = HashCalculator.class.getDeclaredConstructor();
        constructor.setAccessible(true);

        // Act
        HashCalculator instance = constructor.newInstance();

        // Assert
        assertNotNull(instance, "Private constructor should create an instance");
    }

    @Test
    void testInvalidAlgorithmThrowsCryptoException() {
        // Arrange
        byte[] data = TEST_DATA;

        // We need to create a mock HashAlgorithm with an invalid Java name
        // Since HashAlgorithm is an enum, we'll use reflection to invoke the private method
        // directly
        try {
            var method =
                    HashCalculator.class.getDeclaredMethod(
                            "computeHash", byte[].class, String.class);
            method.setAccessible(true);

            // Act & Assert
            InvocationTargetException exception =
                    assertThrows(
                            InvocationTargetException.class,
                            () -> method.invoke(null, data, "INVALID_ALGORITHM_NAME"),
                            "Should throw InvocationTargetException wrapping CryptoException");

            // Verify the cause is CryptoException
            assertNotNull(exception.getCause(), "Should have a cause");
            assertEquals(
                    CryptoException.class,
                    exception.getCause().getClass(),
                    "Cause should be CryptoException");
            assertEquals(
                    "Unknown hash algorithm: INVALID_ALGORITHM_NAME",
                    exception.getCause().getMessage(),
                    "Exception message should contain the invalid algorithm name");

            // Verify the cause has NoSuchAlgorithmException as its cause
            assertNotNull(exception.getCause().getCause(), "CryptoException should have a cause");
            assertEquals(
                    NoSuchAlgorithmException.class,
                    exception.getCause().getCause().getClass(),
                    "CryptoException's cause should be NoSuchAlgorithmException");

        } catch (NoSuchMethodException e) {
            throw new RuntimeException("Method computeHash not found", e);
        }
    }
}
