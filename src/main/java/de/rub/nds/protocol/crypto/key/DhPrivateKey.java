/*
 * Protocol-Attacker - A Framework to create Protocol Analysis Tools
 *
 * Copyright 2023-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.protocol.crypto.key;

import de.rub.nds.protocol.constants.FfdhGoupParameters;
import java.math.BigInteger;

public class DhPrivateKey implements PrivateKeyContainer {

    private BigInteger privateKey;

    private FfdhGoupParameters parameters;

    public DhPrivateKey(BigInteger privateKey, FfdhGoupParameters parameters) {
        this.privateKey = privateKey;
        this.parameters = parameters;
    }

    public BigInteger getPrivateKey() {
        return privateKey;
    }

    public FfdhGoupParameters getParameters() {
        return parameters;
    }
}
