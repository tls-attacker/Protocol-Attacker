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
import de.rub.nds.protocol.crypto.dsa.DsaGroup;
import java.math.BigInteger;

public abstract class DsaParameters implements GroupParameters<BigInteger> {

    private final BigInteger p; // modulus
    private final BigInteger q; // subgroup order
    private final BigInteger g; // generator

    public DsaParameters(BigInteger p, BigInteger q, BigInteger g) {
        this.p = p;
        this.q = q;
        this.g = g;
    }

    public BigInteger getP() {
        return p;
    }

    public BigInteger getQ() {
        return q;
    }

    public BigInteger getG() {
        return g;
    }

    @Override
    public int getElementSizeBits() {
        return p.bitLength();
    }

    @Override
    public int getElementSizeBytes() {
        return (int) Math.ceil(((double) getElementSizeBits()) / 8);
    }

    @Override
    public CyclicGroup<BigInteger> getGroup() {
        return new DsaGroup(this);
    }
}
