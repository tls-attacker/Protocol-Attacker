/*
 * Protocol-Attacker - A Framework to create Protocol Analysis Tools
 *
 * Copyright 2023-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.protocol.exception;

/** Crypto exception */
public class CryptoException extends RuntimeException {

    public CryptoException() {
        super();
    }

    public CryptoException(String message) {
        super(message);
    }

    public CryptoException(Throwable t) {
        super(t);
    }

    public CryptoException(String message, Throwable t) {
        super(message, t);
    }
}
