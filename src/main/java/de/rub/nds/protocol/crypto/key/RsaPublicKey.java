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
import java.math.BigInteger;

/** RSA public key container. Stores the public exponent and modulus for RSA operations. */
public class RsaPublicKey implements PublicKeyContainer {

    /** The public exponent (typically e). */
    private BigInteger publicExponent;

    /** The modulus (n = p*q). */
    private BigInteger modulus;

    /** Default constructor for deserialization. */
    @SuppressWarnings("unused")
    private RsaPublicKey() {
        this.publicExponent = null;
        this.modulus = null;
    }

    /**
     * Constructs an RSA public key with the specified public exponent and modulus.
     *
     * @param publicExponent the public exponent
     * @param modulus the modulus
     */
    public RsaPublicKey(BigInteger publicExponent, BigInteger modulus) {
        this.publicExponent = publicExponent;
        this.modulus = modulus;
    }

    /**
     * Gets the public exponent.
     *
     * @return the public exponent
     */
    public BigInteger getPublicExponent() {
        return publicExponent;
    }

    /**
     * Sets the public exponent.
     *
     * @param publicExponent the public exponent to set
     */
    public void setPublicExponent(BigInteger publicExponent) {
        this.publicExponent = publicExponent;
    }

    /**
     * Gets the modulus.
     *
     * @return the modulus
     */
    public BigInteger getModulus() {
        return modulus;
    }

    /**
     * Sets the modulus.
     *
     * @param modulus the modulus to set
     */
    public void setModulus(BigInteger modulus) {
        this.modulus = modulus;
    }

    /**
     * Returns the bit length of the modulus.
     *
     * @return the bit length of the modulus
     */
    @Override
    public int length() {
        return modulus.bitLength();
    }

    /**
     * Returns a hash code value for this RSA public key.
     *
     * @return a hash code value for this object
     */
    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((publicExponent == null) ? 0 : publicExponent.hashCode());
        result = prime * result + ((modulus == null) ? 0 : modulus.hashCode());
        return result;
    }

    /**
     * Indicates whether some other object is "equal to" this RSA public key.
     *
     * @param obj the reference object with which to compare
     * @return true if this object is the same as the obj argument; false otherwise
     */
    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (obj == null) return false;
        if (getClass() != obj.getClass()) return false;
        RsaPublicKey other = (RsaPublicKey) obj;
        if (publicExponent == null) {
            if (other.publicExponent != null) return false;
        } else if (!publicExponent.equals(other.publicExponent)) return false;
        if (modulus == null) {
            if (other.modulus != null) return false;
        } else if (!modulus.equals(other.modulus)) return false;
        return true;
    }

    /**
     * Returns the asymmetric algorithm type for this key.
     *
     * @return AsymmetricAlgorithmType.RSA
     */
    @Override
    public AsymmetricAlgorithmType getAlgorithmType() {
        return AsymmetricAlgorithmType.RSA;
    }
}
