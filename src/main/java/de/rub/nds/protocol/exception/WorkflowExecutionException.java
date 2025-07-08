/*
 * Protocol-Attacker - A Framework to create Protocol Analysis Tools
 *
 * Copyright 2023-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.protocol.exception;

/** Thrown when workflow execution encounters fatal errors or invalid states. */
public class WorkflowExecutionException extends RuntimeException {

    /** Constructs a new WorkflowExecutionException with no detail message. */
    public WorkflowExecutionException() {
        super();
    }

    /**
     * Constructs a new WorkflowExecutionException with the specified detail message.
     *
     * @param message The detail message
     */
    public WorkflowExecutionException(String message) {
        super(message);
    }

    /**
     * Constructs a new WorkflowExecutionException with the specified detail message and cause.
     *
     * @param message The detail message
     * @param t The cause of the exception
     */
    public WorkflowExecutionException(String message, Throwable t) {
        super(message, t);
    }

    /**
     * Constructs a new WorkflowExecutionException with the specified cause.
     *
     * @param throwable The cause of the exception
     */
    public WorkflowExecutionException(Throwable throwable) {
        super(throwable);
    }
}
