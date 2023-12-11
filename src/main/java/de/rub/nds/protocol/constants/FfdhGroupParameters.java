/*
 * Protocol-Attacker - A Framework to create Protocol Analysis Tools
 *
 * Copyright 2023-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.protocol.constants;

import de.rub.nds.protocol.crypto.CyclicGroup;
import de.rub.nds.protocol.crypto.ffdh.FfdhGroup;
import java.math.BigInteger;

public abstract class FfdhGroupParameters implements GroupParameters<BigInteger> {

    private final BigInteger generator;
    private final BigInteger modulus;

    public FfdhGroupParameters(BigInteger generator, BigInteger modulus) {
        this.generator = generator;
        this.modulus = modulus;
    }

    public BigInteger getGenerator() {
        return generator;
    }

    public BigInteger getModulus() {
        return modulus;
    }

    @Override
    public int getElementSizeBits() {
        return modulus.bitLength();
    }

    @Override
    public int getElementSizeBytes() {
        return (int) Math.ceil(((double) getElementSizeBits()) / 8);
    }

    @Override
    public CyclicGroup<BigInteger> getGroup() {
        return new FfdhGroup(this);
    }
}
