/*
 * Protocol-Attacker - A framework to create protocol analysis tools
 *
 * Copyright 2023-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.protocol.crypto.ffdh;

import de.rub.nds.protocol.constants.FfdhGoupParameters;
import java.math.BigInteger;

public class ExplicitFfdhGroup implements FfdhGoupParameters {

    private BigInteger modulus;
    private BigInteger generator;

    public ExplicitFfdhGroup(BigInteger modulus, BigInteger generator) {
        this.modulus = modulus;
        this.generator = generator;
    }

    @Override
    public BigInteger getModulus() {
        return modulus;
    }

    @Override
    public BigInteger getGenerator() {
        return generator;
    }

    @Override
    public int getElementSize() {
        return modulus.bitLength();
    }
}
