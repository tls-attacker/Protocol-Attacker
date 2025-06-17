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

class CryptoExceptionTest {

    private static final String TEST_MESSAGE = "Test crypto exception message";
    private static final Exception TEST_CAUSE = new IllegalArgumentException("Test cause");

    @Test
    void testDefaultConstructor() {
        CryptoException exception = new CryptoException();
        assertNull(exception.getMessage());
        assertNull(exception.getCause());
    }

    @Test
    void testMessageConstructor() {
        CryptoException exception = new CryptoException(TEST_MESSAGE);
        assertEquals(TEST_MESSAGE, exception.getMessage());
        assertNull(exception.getCause());
    }

    @Test
    void testCauseConstructor() {
        CryptoException exception = new CryptoException(TEST_CAUSE);
        assertEquals(TEST_CAUSE.toString(), exception.getMessage());
        assertSame(TEST_CAUSE, exception.getCause());
    }

    @Test
    void testMessageAndCauseConstructor() {
        CryptoException exception = new CryptoException(TEST_MESSAGE, TEST_CAUSE);
        assertEquals(TEST_MESSAGE, exception.getMessage());
        assertSame(TEST_CAUSE, exception.getCause());
    }
}
