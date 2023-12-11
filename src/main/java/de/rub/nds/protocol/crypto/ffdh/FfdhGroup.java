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

public class FfdhGroup implements CyclicGroup<BigInteger> {

    private FfdhGroupParameters parameters;

    public FfdhGroup(FfdhGroupParameters parameters) {
        this.parameters = parameters;
    }

    @Override
    public BigInteger groupOperation(BigInteger a, BigInteger b) {
        return a.multiply(b);
    }

    @Override
    public BigInteger nTimesGroupOperation(BigInteger a, BigInteger scalar) {
        return a.modPow(scalar, parameters.getModulus());
    }

    @Override
    public BigInteger getGenerator() {
        return parameters.getGenerator();
    }

    @Override
    public BigInteger nTimesGroupOperationOnGenerator(BigInteger scalar) {
        return nTimesGroupOperation(parameters.getGenerator(), scalar);
    }

    public BigInteger getModulus() {
        return parameters.getModulus();
    }

    public FfdhGroupParameters getParameters() {
        return parameters;
    }
}
