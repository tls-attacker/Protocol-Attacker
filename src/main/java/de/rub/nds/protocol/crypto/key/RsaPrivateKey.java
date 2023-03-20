/*
 * Protocol-Attacker - A framework to create protocol analysis tools
 *
 * Copyright 2023-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.protocol.crypto.key;

import java.math.BigInteger;

public class RsaPrivateKey implements PrivateKeyContainer {

    private BigInteger privateExponent;

    private BigInteger modulus;

    public RsaPrivateKey(BigInteger privateExponent, BigInteger modulus) {
        this.privateExponent = privateExponent;
        this.modulus = modulus;
    }

    public BigInteger getPrivateExponent() {
        return privateExponent;
    }

    public BigInteger getModulus() {
        return modulus;
    }
}
