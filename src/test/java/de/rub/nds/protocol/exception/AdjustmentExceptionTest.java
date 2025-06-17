/*
 * Protocol-Attacker - A Framework to create Protocol Analysis Tools
 *
 * Copyright 2023-2024 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.protocol.exception;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class AdjustmentExceptionTest {

    private static final String TEST_MESSAGE = "Test adjustment exception message";
    private static final Exception TEST_CAUSE = new IllegalArgumentException("Test cause");

    @Test
    void testDefaultConstructor() {
        AdjustmentException exception = new AdjustmentException();
        assertNull(exception.getMessage());
        assertNull(exception.getCause());
    }

    @Test
    void testMessageConstructor() {
        AdjustmentException exception = new AdjustmentException(TEST_MESSAGE);
        assertEquals(TEST_MESSAGE, exception.getMessage());
        assertNull(exception.getCause());
    }

    @Test
    void testCauseConstructor() {
        AdjustmentException exception = new AdjustmentException(TEST_CAUSE);
        assertEquals(TEST_CAUSE.toString(), exception.getMessage());
        assertSame(TEST_CAUSE, exception.getCause());
    }

    @Test
    void testMessageAndCauseConstructor() {
        AdjustmentException exception = new AdjustmentException(TEST_MESSAGE, TEST_CAUSE);
        assertEquals(TEST_MESSAGE, exception.getMessage());
        assertSame(TEST_CAUSE, exception.getCause());
    }

    @Test
    void testConstructorWithSuppressionEnabled() {
        AdjustmentException exception =
                new AdjustmentException(TEST_MESSAGE, TEST_CAUSE, true, true);

        assertEquals(TEST_MESSAGE, exception.getMessage());
        assertSame(TEST_CAUSE, exception.getCause());

        // Test suppression enabled
        Exception suppressed = new RuntimeException("Suppressed exception");
        exception.addSuppressed(suppressed);
        assertEquals(1, exception.getSuppressed().length);
        assertSame(suppressed, exception.getSuppressed()[0]);
    }

    @Test
    void testConstructorWithSuppressionDisabled() {
        AdjustmentException exception =
                new AdjustmentException(TEST_MESSAGE, TEST_CAUSE, false, true);

        assertEquals(TEST_MESSAGE, exception.getMessage());
        assertSame(TEST_CAUSE, exception.getCause());

        // Test suppression disabled
        Exception suppressed = new RuntimeException("Suppressed exception");
        exception.addSuppressed(suppressed);
        assertEquals(0, exception.getSuppressed().length);
    }

    @Test
    void testConstructorWithWritableStackTraceDisabled() {
        AdjustmentException exception =
                new AdjustmentException(TEST_MESSAGE, TEST_CAUSE, true, false);

        assertEquals(TEST_MESSAGE, exception.getMessage());
        assertSame(TEST_CAUSE, exception.getCause());

        // A non-writable stack trace should be empty
        assertFalse(
                exception.getStackTrace().length > 0,
                "Stack trace should be empty when writableStackTrace is false");
    }

    @Test
    void testConstructorWithWritableStackTraceEnabled() {
        AdjustmentException exception =
                new AdjustmentException(TEST_MESSAGE, TEST_CAUSE, true, true);

        assertEquals(TEST_MESSAGE, exception.getMessage());
        assertSame(TEST_CAUSE, exception.getCause());

        // A writable stack trace should contain stack elements
        assertTrue(
                exception.getStackTrace().length > 0,
                "Stack trace should not be empty when writableStackTrace is true");
    }
}
