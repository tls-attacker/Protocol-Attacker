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

import de.rub.nds.protocol.constants.HashAlgorithm;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.EnumSource.Mode;

class HashCalculatorTest {

    private static final byte[] TEST_DATA =
            "Protocol-Attacker test data".getBytes(StandardCharsets.UTF_8);

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
}
