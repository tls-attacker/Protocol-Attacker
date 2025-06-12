/*
 * Protocol-Attacker - A Framework to create Protocol Analysis Tools
 *
 * Copyright 2023-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.protocol.crypto.key;

import de.rub.nds.protocol.constants.AsymmetricAlgorithmType;
import de.rub.nds.protocol.constants.DsaParameters;
import de.rub.nds.protocol.crypto.dsa.ExplicitDsaParameters;
import java.math.BigInteger;

public class DsaPublicKey implements PublicKeyContainer {

    private BigInteger Y;
    private DsaParameters dsaParameters;

    /** Default constructor for deserialization. */
    @SuppressWarnings("unused")
    private DsaPublicKey() {
        this.Y = null;
        this.dsaParameters = null;
    }

    /**
     * Create a DSA public key with explicit parameters
     *
     * @param Q DSA subgroup order
     * @param Y Public key value
     * @param generator Generator g
     * @param modulus Modulus p
     */
    public DsaPublicKey(BigInteger Q, BigInteger Y, BigInteger generator, BigInteger modulus) {
        this.dsaParameters = new ExplicitDsaParameters(modulus, Q, generator);
        this.Y = Y;
    }

    /**
     * Create a DSA public key using parameter set
     *
     * @param Y Public key value
     * @param dsaParameters DSA parameter set
     */
    public DsaPublicKey(BigInteger Y, DsaParameters dsaParameters) {
        this.dsaParameters = dsaParameters;
        this.Y = Y;
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

    public BigInteger getY() {
        return Y;
    }

    public void setY(BigInteger y) {
        this.Y = y;
    }

    @Override
    public int length() {
        return getModulus().bitLength();
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((dsaParameters == null) ? 0 : dsaParameters.hashCode());
        result = prime * result + ((Y == null) ? 0 : Y.hashCode());
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (obj == null) return false;
        if (getClass() != obj.getClass()) return false;
        DsaPublicKey other = (DsaPublicKey) obj;
        if (dsaParameters == null) {
            if (other.dsaParameters != null) return false;
        } else if (!dsaParameters.equals(other.dsaParameters)) return false;
        if (Y == null) {
            if (other.Y != null) return false;
        } else if (!Y.equals(other.Y)) return false;
        return true;
    }

    @Override
    public AsymmetricAlgorithmType getAlgorithmType() {
        return AsymmetricAlgorithmType.DSA;
    }
}
