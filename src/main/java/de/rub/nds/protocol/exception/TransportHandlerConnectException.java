/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.protocol.exception;

public class TransportHandlerConnectException extends RuntimeException {

    public TransportHandlerConnectException() {
    }

    public TransportHandlerConnectException(String string) {
        super(string);
    }

    public TransportHandlerConnectException(String string, Throwable throwable) {
        super(string, throwable);
    }

    public TransportHandlerConnectException(Throwable throwable) {
        super(throwable);
    }

    public TransportHandlerConnectException(String string, Throwable throwable, boolean bln, boolean bln1) {
        super(string, throwable, bln, bln1);
    }
}
