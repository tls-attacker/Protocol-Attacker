/*
 * Protocol-Attacker - A Framework to create Protocol Analysis Tools
 *
 * Copyright 2023-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.protocol.exception;

public class BouncyCastleNotLoadedException extends RuntimeException {
    /** Constructs a new BouncyCastleNotLoadedException with no detail message. */
    public BouncyCastleNotLoadedException() {
        super();
    }

    /**
     * Constructs a new BouncyCastleNotLoadedException with the specified detail message.
     *
     * @param message the detail message
     */
    public BouncyCastleNotLoadedException(String message) {
        super(message);
    }

    /**
     * Constructs a new BouncyCastleNotLoadedException with the specified detail message and cause.
     *
     * @param message the detail message
     * @param cause the cause of the exception
     */
    public BouncyCastleNotLoadedException(String message, Throwable cause) {
        super(message, cause);
    }
}
