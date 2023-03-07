package de.rub.nds.protocol.crypto.key;

import java.math.BigInteger;

public class DhPublicKey {

    private BigInteger modulus;
    private BigInteger generator;
    private BigInteger publicKey;

    public DhPublicKey(BigInteger publicKey, BigInteger generator, BigInteger modulus) {
        this.modulus = modulus;
        this.generator = generator;
        this.publicKey = publicKey;
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

    public BigInteger getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(BigInteger publicKey) {
        this.publicKey = publicKey;
    }

}
