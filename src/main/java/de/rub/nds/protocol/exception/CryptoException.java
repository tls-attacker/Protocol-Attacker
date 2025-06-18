/*
 * Protocol-Attacker - A Framework to create Protocol Analysis Tools
 *
 * Copyright 2023-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.protocol.exception;

/** Thrown when cryptographic operations fail or produce unexpected results. */
public class CryptoException extends RuntimeException {

    /** Constructs a new CryptoException with no detail message. */
    public CryptoException() {
        super();
    }

    /**
     * Constructs a new CryptoException with the specified detail message.
     *
     * @param message The detail message
     */
    public CryptoException(String message) {
        super(message);
    }

    /**
     * Constructs a new CryptoException with the specified cause.
     *
     * @param t The cause of the exception
     */
    public CryptoException(Throwable t) {
        super(t);
    }

    /**
     * Constructs a new CryptoException with the specified detail message and cause.
     *
     * @param message The detail message
     * @param t The cause of the exception
     */
    public CryptoException(String message, Throwable t) {
        super(message, t);
    }
}
