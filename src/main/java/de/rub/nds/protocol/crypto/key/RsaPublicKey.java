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

    @Override
    public int length() {
        return modulus.bitLength();
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((publicExponent == null) ? 0 : publicExponent.hashCode());
        result = prime * result + ((modulus == null) ? 0 : modulus.hashCode());
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        RsaPublicKey other = (RsaPublicKey) obj;
        if (publicExponent == null) {
            if (other.publicExponent != null)
                return false;
        } else if (!publicExponent.equals(other.publicExponent))
            return false;
        if (modulus == null) {
            if (other.modulus != null)
                return false;
        } else if (!modulus.equals(other.modulus))
            return false;
        return true;
    }
}
