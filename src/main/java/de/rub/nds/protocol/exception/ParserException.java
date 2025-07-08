/*
 * Protocol-Attacker - A Framework to create Protocol Analysis Tools
 *
 * Copyright 2023-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.protocol.exception;

/** Thrown when parsing protocol messages or data structures fails. */
public class ParserException extends RuntimeException {

    /** Constructs a new ParserException with no detail message. */
    public ParserException() {}

    /**
     * Constructs a new ParserException with the specified detail message.
     *
     * @param message The detail message
     */
    public ParserException(String message) {
        super(message);
    }

    /**
     * Constructs a new ParserException with the specified detail message and cause.
     *
     * @param message The detail message
     * @param cause The cause of the exception
     */
    public ParserException(String message, Throwable cause) {
        super(message, cause);
    }

    /**
     * Constructs a new ParserException with the specified cause.
     *
     * @param cause The cause of the exception
     */
    public ParserException(Throwable cause) {
        super(cause);
    }

    /**
     * Constructs a new ParserException with the specified detail message, cause, suppression
     * enabled or disabled, and writable stack trace enabled or disabled.
     *
     * @param message The detail message
     * @param cause The cause of the exception
     * @param enableSuppression Whether suppression is enabled or disabled
     * @param writableStackTrace Whether the stack trace should be writable
     */
    public ParserException(
            String message,
            Throwable cause,
            boolean enableSuppression,
            boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }
}
