/*
 * Protocol-Attacker - A Framework to create Protocol Analysis Tools
 *
 * Copyright 2023-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.protocol.crypto.key;

import de.rub.nds.protocol.constants.DsaParameters;
import java.math.BigInteger;

public class DsaPrivateKey implements PrivateKeyContainer {
    private BigInteger modulus;
    private BigInteger generator;
    private BigInteger Q;
    private BigInteger X;
    private BigInteger K;
    private DsaParameters dsaParameters;

    public DsaPrivateKey(
            BigInteger Q, BigInteger X, BigInteger K, BigInteger generator, BigInteger modulus) {
        this.modulus = modulus;
        this.generator = generator;
        this.Q = Q;
        this.X = X;
        this.K = K;
    }

    public DsaPrivateKey(BigInteger X, BigInteger K, DsaParameters dsaParameters) {
        this.dsaParameters = dsaParameters;
        this.modulus = dsaParameters.getP();
        this.generator = dsaParameters.getG();
        this.Q = dsaParameters.getQ();
        this.X = X;
        this.K = K;
    }

    public DsaParameters getDsaParameters() {
        return dsaParameters;
    }

    public void setDsaParameters(DsaParameters dsaParameters) {
        this.dsaParameters = dsaParameters;
        this.modulus = dsaParameters.getP();
        this.generator = dsaParameters.getG();
        this.Q = dsaParameters.getQ();
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

    public void setGenerator(BigInteger generator) {
        this.generator = generator;
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
