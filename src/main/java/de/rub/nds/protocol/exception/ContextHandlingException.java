/*
 * Protocol-Attacker - A Framework to create Protocol Analysis Tools
 *
 * Copyright 2023-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.protocol.exception;

public class ContextHandlingException extends RuntimeException {

    public ContextHandlingException() {
        super();
    }

    public ContextHandlingException(String message) {
        super(message);
    }

    public ContextHandlingException(String message, Throwable cause) {
        super(message, cause);
    }
}
