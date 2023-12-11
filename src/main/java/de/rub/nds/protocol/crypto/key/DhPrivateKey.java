/*
 * Protocol-Attacker - A Framework to create Protocol Analysis Tools
 *
 * Copyright 2023-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.protocol.crypto.key;

import de.rub.nds.protocol.constants.FfdhGroupParameters;
import java.math.BigInteger;

public class DhPrivateKey implements PrivateKeyContainer {

    private BigInteger privateKey;

    private FfdhGroupParameters parameters;

    public DhPrivateKey(BigInteger privateKey, FfdhGroupParameters parameters) {
        this.privateKey = privateKey;
        this.parameters = parameters;
    }

    public BigInteger getPrivateKey() {
        return privateKey;
    }

    public FfdhGroupParameters getParameters() {
        return parameters;
    }
}
