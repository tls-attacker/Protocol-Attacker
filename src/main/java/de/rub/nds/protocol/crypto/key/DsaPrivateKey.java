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
import de.rub.nds.protocol.crypto.dsa.ExplicitDsaParameters;
import java.math.BigInteger;

public class DsaPrivateKey implements PrivateKeyContainer {
    private BigInteger X;
    private BigInteger K;
    private DsaParameters dsaParameters;

    /** Default constructor for deserialization. */
    @SuppressWarnings("unused")
    private DsaPrivateKey() {
        this.X = null;
        this.K = null;
        this.dsaParameters = null;
    }

    /**
     * Create a DSA private key with explicit parameters
     *
     * @param Q DSA subgroup order
     * @param X Private key value
     * @param K Nonce
     * @param generator Generator g
     * @param modulus Modulus p
     */
    public DsaPrivateKey(
            BigInteger Q, BigInteger X, BigInteger K, BigInteger generator, BigInteger modulus) {
        this.dsaParameters = new ExplicitDsaParameters(modulus, Q, generator);
        this.X = X;
        this.K = K;
    }

    /**
     * Create a DSA private key using parameter set
     *
     * @param X Private key value
     * @param K Nonce
     * @param dsaParameters DSA parameter set
     */
    public DsaPrivateKey(BigInteger X, BigInteger K, DsaParameters dsaParameters) {
        this.dsaParameters = dsaParameters;
        this.X = X;
        this.K = K;
    }

    public DsaParameters getDsaParameters() {
        return dsaParameters;
    }

    public void setDsaParameters(DsaParameters dsaParameters) {
        this.dsaParameters = dsaParameters;
    }

    public BigInteger getModulus() {
        return dsaParameters.getP();
    }

    public BigInteger getGenerator() {
        return dsaParameters.getG();
    }

    public BigInteger getQ() {
        return dsaParameters.getQ();
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
