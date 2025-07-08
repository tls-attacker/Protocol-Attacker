/*
 * Protocol-Attacker - A Framework to create Protocol Analysis Tools
 *
 * Copyright 2023-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.protocol.exception;

public class TransportHandlerConnectException extends RuntimeException {

    /** Constructs a new TransportHandlerConnectException with no detail message. */
    public TransportHandlerConnectException() {}

    /**
     * Constructs a new TransportHandlerConnectException with the specified detail message.
     *
     * @param string The detail message
     */
    public TransportHandlerConnectException(String string) {
        super(string);
    }

    /**
     * Constructs a new TransportHandlerConnectException with the specified detail message and
     * cause.
     *
     * @param string The detail message
     * @param throwable The cause of the exception
     */
    public TransportHandlerConnectException(String string, Throwable throwable) {
        super(string, throwable);
    }

    /**
     * Constructs a new TransportHandlerConnectException with the specified cause.
     *
     * @param throwable The cause of the exception
     */
    public TransportHandlerConnectException(Throwable throwable) {
        super(throwable);
    }

    /**
     * Constructs a new TransportHandlerConnectException with the specified detail message, cause,
     * suppression enabled or disabled, and writable stack trace enabled or disabled.
     *
     * @param string The detail message
     * @param throwable The cause of the exception
     * @param bln Whether suppression is enabled or disabled
     * @param bln1 Whether the stack trace should be writable
     */
    public TransportHandlerConnectException(
            String string, Throwable throwable, boolean bln, boolean bln1) {
        super(string, throwable, bln, bln1);
    }
}
