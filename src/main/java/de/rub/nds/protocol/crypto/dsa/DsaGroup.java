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

    public BigInteger getP() {
        return parameters.getP();
    }

    public BigInteger getQ() {
        return parameters.getQ();
    }

    public DsaParameters getParameters() {
        return parameters;
    }
}
