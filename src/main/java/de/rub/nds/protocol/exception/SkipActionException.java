/*
 * Protocol-Attacker - A Framework to create Protocol Analysis Tools
 *
 * Copyright 2023-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.protocol.exception;

public class SkipActionException extends RuntimeException {

    public SkipActionException() {}

    public SkipActionException(String message) {
        super(message);
    }

    public SkipActionException(String message, Throwable cause) {
        super(message, cause);
    }

    public SkipActionException(Throwable cause) {
        super(cause);
    }

    public SkipActionException(
            String message,
            Throwable cause,
            boolean enableSuppression,
            boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }
}
