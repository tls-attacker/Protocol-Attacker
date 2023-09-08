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
    public BouncyCastleNotLoadedException() {
        super();
    }

    public BouncyCastleNotLoadedException(String message) {
        super(message);
    }

    public BouncyCastleNotLoadedException(String message, Throwable cause) {
        super(message, cause);
    }
}
