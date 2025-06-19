/*
 * Protocol-Attacker - A Framework to create Protocol Analysis Tools
 *
 * Copyright 2023-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.protocol.crypto.ffdh;

import de.rub.nds.protocol.constants.FfdhGroupParameters;
import de.rub.nds.protocol.crypto.CyclicGroup;
import java.math.BigInteger;

/**
 * Represents a finite field Diffie-Hellman (FFDH) group that implements cyclic group operations.
 * This class provides group operations for FFDH groups as defined by various standards.
 */
public class FfdhGroup implements CyclicGroup<BigInteger> {

    private FfdhGroupParameters parameters;

    /**
     * Constructs a new FFDH group with the specified parameters.
     *
     * @param parameters the FFDH group parameters containing the modulus and generator
     */
    public FfdhGroup(FfdhGroupParameters parameters) {
        this.parameters = parameters;
    }

    /**
     * Performs the group operation (multiplication) on two group elements.
     *
     * @param a the first group element
     * @param b the second group element
     * @return the result of multiplying a and b
     */
    @Override
    public BigInteger groupOperation(BigInteger a, BigInteger b) {
        return a.multiply(b);
    }

    /**
     * Performs the group operation n times on a group element (modular exponentiation).
     *
     * @param a the group element
     * @param scalar the number of times to apply the group operation
     * @return the result of a^scalar mod modulus
     */
    @Override
    public BigInteger nTimesGroupOperation(BigInteger a, BigInteger scalar) {
        return a.modPow(scalar, parameters.getModulus());
    }

    /**
     * Returns the generator of this FFDH group.
     *
     * @return the generator element
     */
    @Override
    public BigInteger getGenerator() {
        return parameters.getGenerator();
    }

    /**
     * Performs the group operation n times on the generator (generator^scalar mod modulus).
     *
     * @param scalar the exponent to apply to the generator
     * @return the result of generator^scalar mod modulus
     */
    @Override
    public BigInteger nTimesGroupOperationOnGenerator(BigInteger scalar) {
        return nTimesGroupOperation(parameters.getGenerator(), scalar);
    }

    /**
     * Returns the modulus of this FFDH group.
     *
     * @return the modulus (prime p)
     */
    public BigInteger getModulus() {
        return parameters.getModulus();
    }

    /**
     * Returns the complete FFDH group parameters.
     *
     * @return the FFDH group parameters containing modulus and generator
     */
    public FfdhGroupParameters getParameters() {
        return parameters;
    }
}
