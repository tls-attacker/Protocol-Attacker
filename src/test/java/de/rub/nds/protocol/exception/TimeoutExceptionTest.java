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
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;

import org.junit.jupiter.api.Test;

class TimeoutExceptionTest {

    private static final String TEST_MESSAGE = "Test timeout error message";
    private static final Exception TEST_CAUSE = new IllegalArgumentException("Test cause");

    @Test
    void testDefaultConstructor() {
        TimeoutException exception = new TimeoutException();
        assertNull(exception.getMessage());
        assertNull(exception.getCause());
    }

    @Test
    void testMessageConstructor() {
        TimeoutException exception = new TimeoutException(TEST_MESSAGE);
        assertEquals(TEST_MESSAGE, exception.getMessage());
        assertNull(exception.getCause());
    }

    @Test
    void testMessageAndCauseConstructor() {
        TimeoutException exception = new TimeoutException(TEST_MESSAGE, TEST_CAUSE);
        assertEquals(TEST_MESSAGE, exception.getMessage());
        assertSame(TEST_CAUSE, exception.getCause());
    }

    @Test
    void testExceptionThrowAndCatch() {
        try {
            throwTimeoutException();
        } catch (TimeoutException e) {
            assertEquals(TEST_MESSAGE, e.getMessage());
            assertSame(TEST_CAUSE, e.getCause());
        }
    }

    private void throwTimeoutException() {
        throw new TimeoutException(TEST_MESSAGE, TEST_CAUSE);
    }
}
