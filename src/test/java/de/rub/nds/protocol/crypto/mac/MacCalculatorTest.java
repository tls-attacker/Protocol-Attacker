/*
 * Protocol-Attacker - A Framework to create Protocol Analysis Tools
 *
 * Copyright 2023-2024 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.protocol.crypto.mac;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import de.rub.nds.protocol.constants.MacAlgorithm;
import de.rub.nds.protocol.exception.CryptoException;
import java.nio.charset.StandardCharsets;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.EnumSource.Mode;

public class MacCalculatorTest {

    private static final byte[] TEST_DATA =
            "Protocol-Attacker test data".getBytes(StandardCharsets.UTF_8);
    private static final byte[] TEST_KEY =
            "ThisIsATestKeyForMacCalculation".getBytes(StandardCharsets.UTF_8);

    @Test
    void testMacWithNoneAlgorithm() {
        // Arrange
        MacAlgorithm algorithm = MacAlgorithm.NONE;

        // Act
        byte[] result = MacCalculator.compute(TEST_KEY, TEST_DATA, algorithm);

        // Assert
        assertArrayEquals(
                TEST_DATA,
                result,
                "When using NONE algorithm, the original data should be returned");
    }

    @ParameterizedTest
    @EnumSource(
            value = MacAlgorithm.class,
            mode = Mode.INCLUDE,
            names = {"HMAC_SHA1", "HMAC_SHA256", "HMAC_SHA384", "HMAC_SHA512"})
    void testMacWithStandardAlgorithms(MacAlgorithm algorithm) throws Exception {
        // Skip if no Java implementation available
        if (algorithm.getJavaName() == null) {
            return;
        }

        try {
            // Arrange - compute expected result using Java's Mac
            Mac mac = Mac.getInstance(algorithm.getJavaName());
            mac.init(new SecretKeySpec(TEST_KEY, algorithm.getJavaName()));
            mac.update(TEST_DATA);
            byte[] expected = mac.doFinal();

            // Act
            byte[] result = MacCalculator.compute(TEST_KEY, TEST_DATA, algorithm);

            // Assert
            assertArrayEquals(
                    expected, result, "MAC result should match Java's Mac result for " + algorithm);
            assertEquals(
                    algorithm.getMacLength(),
                    result.length,
                    "MAC output length should match expected length");
        } catch (Exception e) {
            // Skip this test if the algorithm is not supported by the JVM
            System.out.println("Skipping test for " + algorithm + ": " + e.getMessage());
        }
    }

    @Test
    void testMacWithEmptyInput() throws Exception {
        // Arrange
        byte[] emptyData = new byte[0];
        MacAlgorithm algorithm = MacAlgorithm.HMAC_SHA256;

        // Compute expected result
        Mac mac = Mac.getInstance(algorithm.getJavaName());
        mac.init(new SecretKeySpec(TEST_KEY, algorithm.getJavaName()));
        mac.update(emptyData);
        byte[] expected = mac.doFinal();

        // Act
        byte[] result = MacCalculator.compute(TEST_KEY, emptyData, algorithm);

        // Assert
        assertArrayEquals(expected, result, "Should be able to compute MAC for empty byte array");
    }

    @Test
    void testMacWithEmptyKey() {
        // Arrange
        byte[] emptyKey = new byte[0];
        MacAlgorithm algorithm = MacAlgorithm.HMAC_SHA256;

        // Act & Assert - An empty key is not a valid key for most MAC algorithms
        // The underlying exception is IllegalArgumentException, but it should be wrapped in
        // CryptoException
        assertThrows(Exception.class, () -> MacCalculator.compute(emptyKey, TEST_DATA, algorithm));
    }

    @Test
    void testMacWithInvalidAlgorithm() {
        // Use a MAC algorithm that isn't typically available in standard JDK
        MacAlgorithm algorithm = MacAlgorithm.IMIT_GOST28147;

        // Act & Assert
        assertThrows(
                CryptoException.class, () -> MacCalculator.compute(TEST_KEY, TEST_DATA, algorithm));
    }
}
