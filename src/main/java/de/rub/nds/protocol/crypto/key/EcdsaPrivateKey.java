/*
 * Protocol-Attacker - A Framework to create Protocol Analysis Tools
 *
 * Copyright 2023-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.protocol.crypto.key;

import de.rub.nds.protocol.constants.NamedEllipticCurveParameters;
import java.math.BigInteger;

public class EcdsaPrivateKey implements PrivateKeyContainer {

    private BigInteger privateKey;

    private BigInteger nonce;

    private NamedEllipticCurveParameters parameters;

    public EcdsaPrivateKey(
            BigInteger privateKey, BigInteger nonce, NamedEllipticCurveParameters parameters) {
        this.privateKey = privateKey;
        this.parameters = parameters;
        this.nonce = nonce;
    }

    public BigInteger getPrivateKey() {
        return privateKey;
    }

    public NamedEllipticCurveParameters getParameters() {
        return parameters;
    }

    public BigInteger getNonce() {
        return nonce;
    }
}
