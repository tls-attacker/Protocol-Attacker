/*
 * Protocol-Attacker - A framework to create protocol analysis tools
 *
 * Copyright 2023-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.protocol.exception;

/** Thrown when problems by in the TLS workflow appear. */
public class WorkflowExecutionException extends RuntimeException {

    public WorkflowExecutionException() {
        super();
    }

    public WorkflowExecutionException(String message) {
        super(message);
    }

    public WorkflowExecutionException(String message, Throwable t) {
        super(message, t);
    }

    public WorkflowExecutionException(Throwable throwable) {
        super(throwable);
    }
}
