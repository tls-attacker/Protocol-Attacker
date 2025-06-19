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
import de.rub.nds.protocol.constants.FfdhGroupParameters;
import de.rub.nds.protocol.crypto.ffdh.ExplicitFfdhGroupParameters;
import java.math.BigInteger;

public class DhPublicKey implements PublicKeyContainer {

    private FfdhGroupParameters parameters;

    private BigInteger publicKey;

    /** Default constructor for deserialization. */
    @SuppressWarnings("unused")
    private DhPublicKey() {
        this.parameters = null;
        this.publicKey = null;
    }

    /**
     * Constructs a new DH public key with the specified public key value, generator, and modulus.
     *
     * @param publicKey the public key value
     * @param generator the generator value
     * @param modulus the modulus value
     */
    public DhPublicKey(BigInteger publicKey, BigInteger generator, BigInteger modulus) {
        this.parameters = new ExplicitFfdhGroupParameters(generator, modulus);
        this.publicKey = publicKey;
    }

    /**
     * Constructs a new DH public key with the specified public key value and group parameters.
     *
     * @param publicKey the public key value
     * @param parameters the FFDH group parameters
     */
    public DhPublicKey(BigInteger publicKey, FfdhGroupParameters parameters) {
        this.parameters = parameters;
        this.publicKey = publicKey;
    }

    /**
     * Returns the modulus value from the group parameters.
     *
     * @return the modulus value
     */
    public BigInteger getModulus() {
        return parameters.getModulus();
    }

    /**
     * Returns the generator value from the group parameters.
     *
     * @return the generator value
     */
    public BigInteger getGenerator() {
        return parameters.getGenerator();
    }

    /**
     * Returns the public key value.
     *
     * @return the public key value
     */
    public BigInteger getPublicKey() {
        return publicKey;
    }

    /**
     * Returns the length of the public key in bits.
     *
     * @return the bit length of the modulus
     */
    @Override
    public int length() {
        return getModulus().bitLength();
    }

    /**
     * Returns a hash code value for this DH public key.
     *
     * @return a hash code value for this object
     */
    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((parameters == null) ? 0 : parameters.hashCode());
        result = prime * result + ((publicKey == null) ? 0 : publicKey.hashCode());
        return result;
    }

    /**
     * Indicates whether some other object is equal to this DH public key.
     *
     * @param obj the reference object with which to compare
     * @return true if this object is the same as the obj argument; false otherwise
     */
    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (obj == null) return false;
        if (getClass() != obj.getClass()) return false;
        DhPublicKey other = (DhPublicKey) obj;
        if (parameters == null) {
            if (other.parameters != null) return false;
        } else if (!parameters.equals(other.parameters)) return false;
        if (publicKey == null) {
            if (other.publicKey != null) return false;
        } else if (!publicKey.equals(other.publicKey)) return false;
        return true;
    }

    /**
     * Returns the asymmetric algorithm type for this key.
     *
     * @return the algorithm type (DH)
     */
    @Override
    public AsymmetricAlgorithmType getAlgorithmType() {
        return AsymmetricAlgorithmType.DH;
    }
}
