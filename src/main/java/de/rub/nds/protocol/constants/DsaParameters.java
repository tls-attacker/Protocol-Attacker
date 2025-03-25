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

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((p == null) ? 0 : p.hashCode());
        result = prime * result + ((q == null) ? 0 : q.hashCode());
        result = prime * result + ((g == null) ? 0 : g.hashCode());
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (obj == null) return false;
        if (getClass() != obj.getClass()) return false;
        DsaParameters other = (DsaParameters) obj;
        if (p == null) {
            if (other.p != null) return false;
        } else if (!p.equals(other.p)) return false;
        if (q == null) {
            if (other.q != null) return false;
        } else if (!q.equals(other.q)) return false;
        if (g == null) {
            if (other.g != null) return false;
        } else if (!g.equals(other.g)) return false;
        return true;
    }
}
