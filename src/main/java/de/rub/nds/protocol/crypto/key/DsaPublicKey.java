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

    /**
     * Gets the DSA parameters associated with this public key.
     *
     * @return the DSA parameters
     */
    public DsaParameters getDsaParameters() {
        return dsaParameters;
    }

    /**
     * Sets the DSA parameters for this public key.
     *
     * @param dsaParameters the DSA parameters to set
     */
    public void setDsaParameters(DsaParameters dsaParameters) {
        this.dsaParameters = dsaParameters;
    }

    /**
     * Gets the modulus p from the DSA parameters.
     *
     * @return the modulus p
     */
    public BigInteger getModulus() {
        return dsaParameters.getP();
    }

    /**
     * Gets the generator g from the DSA parameters.
     *
     * @return the generator g
     */
    public BigInteger getGenerator() {
        return dsaParameters.getG();
    }

    /**
     * Gets the subgroup order Q from the DSA parameters.
     *
     * @return the subgroup order Q
     */
    public BigInteger getQ() {
        return dsaParameters.getQ();
    }

    /**
     * Gets the public key value Y.
     *
     * @return the public key value Y
     */
    public BigInteger getY() {
        return Y;
    }

    /**
     * Sets the public key value Y.
     *
     * @param y the public key value to set
     */
    public void setY(BigInteger y) {
        this.Y = y;
    }

    /**
     * Returns the bit length of the modulus.
     *
     * @return the bit length of the modulus
     */
    @Override
    public int length() {
        return getModulus().bitLength();
    }

    /**
     * Returns a hash code value for this DSA public key.
     *
     * @return a hash code value for this object
     */
    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((dsaParameters == null) ? 0 : dsaParameters.hashCode());
        result = prime * result + ((Y == null) ? 0 : Y.hashCode());
        return result;
    }

    /**
     * Indicates whether some other object is "equal to" this DSA public key.
     *
     * @param obj the reference object with which to compare
     * @return true if this object is the same as the obj argument; false otherwise
     */
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

    /**
     * Returns the asymmetric algorithm type for this key.
     *
     * @return AsymmetricAlgorithmType.DSA
     */
    @Override
    public AsymmetricAlgorithmType getAlgorithmType() {
        return AsymmetricAlgorithmType.DSA;
    }
}
