/*
 * Protocol-Attacker - A Framework to create Protocol Analysis Tools
 *
 * Copyright 2023-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.protocol.exception;

/**
 * Thrown when an action fails to execute during workflow processing.
 */
public class ActionExecutionException extends RuntimeException {

    /** Constructs a new ActionExecutionException with no detail message. */
    public ActionExecutionException() {}

    /**
     * Constructs a new ActionExecutionException with the specified detail message.
     *
     * @param message the detail message
     */
    public ActionExecutionException(String message) {
        super(message);
    }

    /**
     * Constructs a new ActionExecutionException with the specified detail message and cause.
     *
     * @param message the detail message
     * @param cause the cause of the exception
     */
    public ActionExecutionException(String message, Throwable cause) {
        super(message, cause);
    }
}
