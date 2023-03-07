package de.rub.nds.protocol.crypto.key;

import java.math.BigInteger;

public class DsaPublicKey implements PublicKeyContainer {

    private BigInteger modulus;
    private BigInteger generator;
    private BigInteger Q;
    private BigInteger X;

    public DsaPublicKey(BigInteger Q, BigInteger X, BigInteger generator, BigInteger modulus) {
        this.Q = Q;
        this.X = X;
        this.generator = generator;
        this.modulus = modulus;
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

    public void setQ(BigInteger Q) {
        this.Q = Q;
    }

    public BigInteger getX() {
        return X;
    }

    public void setX(BigInteger X) {
        this.X = X;
    }

}
