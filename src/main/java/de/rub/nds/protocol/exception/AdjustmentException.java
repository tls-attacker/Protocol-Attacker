/*
 * Protocol-Attacker - A Framework to create Protocol Analysis Tools
 *
 * Copyright 2023-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.protocol.exception;

/** Thrown when message or protocol state adjustments fail. */
public class AdjustmentException extends RuntimeException {

    /** Constructs a new AdjustmentException with no detail message. */
    public AdjustmentException() {}

    /**
     * Constructs a new AdjustmentException with the specified detail message.
     *
     * @param message the detail message
     */
    public AdjustmentException(String message) {
        super(message);
    }

    /**
     * Constructs a new AdjustmentException with the specified detail message and cause.
     *
     * @param message the detail message
     * @param cause the cause of the exception
     */
    public AdjustmentException(String message, Throwable cause) {
        super(message, cause);
    }

    /**
     * Constructs a new AdjustmentException with the specified cause.
     *
     * @param cause the cause of the exception
     */
    public AdjustmentException(Throwable cause) {
        super(cause);
    }

    /**
     * Constructs a new AdjustmentException with the specified detail message, cause, suppression
     * enabled or disabled, and writable stack trace enabled or disabled.
     *
     * @param message the detail message
     * @param cause the cause of the exception
     * @param enableSuppression whether or not suppression is enabled or disabled
     * @param writableStackTrace whether or not the stack trace should be writable
     */
    public AdjustmentException(
            String message,
            Throwable cause,
            boolean enableSuppression,
            boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }
}
