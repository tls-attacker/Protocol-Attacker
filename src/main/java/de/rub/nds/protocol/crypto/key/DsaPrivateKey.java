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

public class DsaPrivateKey implements PrivateKeyContainer {
    private BigInteger modulus;
    private BigInteger generator;

    private BigInteger Q;

    private BigInteger X;

    private BigInteger K;

    public DsaPrivateKey(
            BigInteger Q, BigInteger X, BigInteger K, BigInteger generator, BigInteger modulus) {
        this.modulus = modulus;
        this.generator = generator;
        this.Q = Q;
        this.X = X;
        this.K = K;
    }

    public BigInteger getModulus() {
        return modulus;
    }

    public void setModulus(BigInteger modulus) {
        this.modulus = modulus;
    }

    public BigInteger getGenerator() {
        return generator;
    }

    public void setGenerator(BigInteger generaotr) {
        this.generator = generaotr;
    }

    public BigInteger getQ() {
        return Q;
    }

    public void setQ(BigInteger q) {
        Q = q;
    }

    public BigInteger getX() {
        return X;
    }

    public void setX(BigInteger x) {
        X = x;
    }

    public BigInteger getK() {
        return K;
    }

    public void setK(BigInteger k) {
        K = k;
    }
}
