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

public class ConfigurationExceptionTest {

    private static final String TEST_MESSAGE = "Test configuration error message";
    private static final Exception TEST_CAUSE = new IllegalArgumentException("Test cause");

    @Test
    public void testDefaultConstructor() {
        ConfigurationException exception = new ConfigurationException();
        assertNull(exception.getMessage());
        assertNull(exception.getCause());
    }

    @Test
    public void testMessageConstructor() {
        ConfigurationException exception = new ConfigurationException(TEST_MESSAGE);
        assertEquals(TEST_MESSAGE, exception.getMessage());
        assertNull(exception.getCause());
    }

    @Test
    public void testMessageAndCauseConstructor() {
        ConfigurationException exception = new ConfigurationException(TEST_MESSAGE, TEST_CAUSE);
        assertEquals(TEST_MESSAGE, exception.getMessage());
        assertSame(TEST_CAUSE, exception.getCause());
    }

    @Test
    public void testExceptionChaining() {
        // Test exception chaining
        RuntimeException rootCause = new RuntimeException("Root cause");
        IllegalArgumentException intermediateCause =
                new IllegalArgumentException("Intermediate", rootCause);
        ConfigurationException exception =
                new ConfigurationException("Top level", intermediateCause);

        assertEquals("Top level", exception.getMessage());
        assertSame(intermediateCause, exception.getCause());
        assertSame(rootCause, exception.getCause().getCause());
    }
}
