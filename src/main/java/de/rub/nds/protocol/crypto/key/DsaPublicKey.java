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

public class DsaPublicKey implements PublicKeyContainer {

    private BigInteger modulus;
    private BigInteger generator;
    private BigInteger Q;
    private BigInteger Y;

    public DsaPublicKey(BigInteger Q, BigInteger Y, BigInteger generator, BigInteger modulus) {
        this.Q = Q;
        this.Y = Y;
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

    public BigInteger getY() {
        return Y;
    }

    public void setY(BigInteger X) {
        this.Y = X;
    }

    @Override
    public int length() {
        return modulus.bitLength();
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((modulus == null) ? 0 : modulus.hashCode());
        result = prime * result + ((generator == null) ? 0 : generator.hashCode());
        result = prime * result + ((Q == null) ? 0 : Q.hashCode());
        result = prime * result + ((Y == null) ? 0 : Y.hashCode());
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (obj == null) return false;
        if (getClass() != obj.getClass()) return false;
        DsaPublicKey other = (DsaPublicKey) obj;
        if (modulus == null) {
            if (other.modulus != null) return false;
        } else if (!modulus.equals(other.modulus)) return false;
        if (generator == null) {
            if (other.generator != null) return false;
        } else if (!generator.equals(other.generator)) return false;
        if (Q == null) {
            if (other.Q != null) return false;
        } else if (!Q.equals(other.Q)) return false;
        if (Y == null) {
            if (other.Y != null) return false;
        } else if (!Y.equals(other.Y)) return false;
        return true;
    }
}
