/*
 * Protocol-Attacker - A Framework to create Protocol Analysis Tools
 *
 * Copyright 2023-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.protocol.crypto.dsa;

import de.rub.nds.protocol.constants.DsaParameters;
import de.rub.nds.protocol.crypto.CyclicGroup;
import java.math.BigInteger;

public class DsaGroup implements CyclicGroup<BigInteger> {

    private final DsaParameters parameters;

    /**
     * Constructs a new DsaGroup with the specified DSA parameters.
     *
     * @param parameters The DSA parameters defining the group
     */
    public DsaGroup(DsaParameters parameters) {
        this.parameters = parameters;
    }

    @Override
    public BigInteger groupOperation(BigInteger a, BigInteger b) {
        return a.multiply(b).mod(parameters.getP());
    }

    @Override
    public BigInteger nTimesGroupOperation(BigInteger a, BigInteger scalar) {
        return a.modPow(scalar, parameters.getP());
    }

    @Override
    public BigInteger getGenerator() {
        return parameters.getG();
    }

    @Override
    public BigInteger nTimesGroupOperationOnGenerator(BigInteger scalar) {
        return nTimesGroupOperation(parameters.getG(), scalar);
    }

    /**
     * Returns the prime modulus p of the DSA group.
     *
     * @return The prime modulus p
     */
    public BigInteger getP() {
        return parameters.getP();
    }

    /**
     * Returns the prime order q of the subgroup.
     *
     * @return The prime order q
     */
    public BigInteger getQ() {
        return parameters.getQ();
    }

    /**
     * Returns the DSA parameters of this group.
     *
     * @return The DSA parameters
     */
    public DsaParameters getParameters() {
        return parameters;
    }
}
