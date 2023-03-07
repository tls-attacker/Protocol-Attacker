package de.rub.nds.protocol.crypto.key;

import java.math.BigInteger;

public class RsaPublicKey implements PublicKeyContainer {

    private BigInteger publicExponent;

    private BigInteger modulus;

    public RsaPublicKey(BigInteger publicExponent, BigInteger modulus) {
        this.publicExponent = publicExponent;
        this.modulus = modulus;
    }

    public BigInteger getPublicExponent() {
        return publicExponent;
    }

    public void setPublicExponent(BigInteger publicExponent) {
        this.publicExponent = publicExponent;
    }

    public BigInteger getModulus() {
        return modulus;
    }

    public void setModulus(BigInteger modulus) {
        this.modulus = modulus;
    }
}
