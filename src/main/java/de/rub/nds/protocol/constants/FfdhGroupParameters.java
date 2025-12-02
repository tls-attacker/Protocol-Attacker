/*
 * Protocol-Attacker - A Framework to create Protocol Analysis Tools
 *
 * Copyright 2023-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.protocol.constants;

import com.fasterxml.jackson.annotation.JsonTypeInfo;
import de.rub.nds.protocol.crypto.CyclicGroup;
import de.rub.nds.protocol.crypto.ffdh.FfdhGroup;
import java.math.BigInteger;

/**
 * Abstract base class for Finite Field Diffie-Hellman group parameters. Provides generator and
 * modulus for FFDH operations.
 */
@JsonTypeInfo(use = JsonTypeInfo.Id.CLASS, include = JsonTypeInfo.As.PROPERTY, property = "@class")
public abstract class FfdhGroupParameters implements GroupParameters<BigInteger> {

    /** The generator element of the group. */
    private final BigInteger generator;

    /** The prime modulus defining the finite field. */
    private final BigInteger modulus;

    /**
     * Constructs a new FfdhGroupParameters instance with the specified generator and modulus.
     *
     * @param generator the generator of the finite field Diffie-Hellman group
     * @param modulus the modulus (prime) of the finite field Diffie-Hellman group
     */
    public FfdhGroupParameters(BigInteger generator, BigInteger modulus) {
        this.generator = generator;
        this.modulus = modulus;
    }

    /**
     * Returns the generator of this finite field Diffie-Hellman group.
     *
     * @return the generator
     */
    public BigInteger getGenerator() {
        return generator;
    }

    /**
     * Returns the modulus (prime) of this finite field Diffie-Hellman group.
     *
     * @return the modulus
     */
    public BigInteger getModulus() {
        return modulus;
    }

    /**
     * Returns the size of group elements in bits.
     *
     * @return the bit length of the modulus
     */
    @Override
    public int getElementSizeBits() {
        return modulus.bitLength();
    }

    /**
     * Returns the size of group elements in bytes.
     *
     * @return the byte length required to represent group elements
     */
    @Override
    public int getElementSizeBytes() {
        return (int) Math.ceil(((double) getElementSizeBits()) / 8);
    }

    /**
     * Returns the cyclic group associated with these FFDH parameters.
     *
     * @return a FfdhGroup instance with these parameters
     */
    @Override
    public CyclicGroup<BigInteger> getGroup() {
        return new FfdhGroup(this);
    }
}
