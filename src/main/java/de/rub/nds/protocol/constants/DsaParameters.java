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

/**
 * Abstract base class for DSA (Digital Signature Algorithm) parameters.
 * Provides the prime modulus p, subgroup order q, and generator g.
 */
public abstract class DsaParameters implements GroupParameters<BigInteger> {

    private final BigInteger p; // modulus
    private final BigInteger q; // subgroup order
    private final BigInteger g; // generator

    /**
     * Constructs a new DsaParameters instance with the specified DSA domain parameters.
     *
     * @param p the DSA modulus
     * @param q the DSA subgroup order
     * @param g the DSA generator
     */
    public DsaParameters(BigInteger p, BigInteger q, BigInteger g) {
        this.p = p;
        this.q = q;
        this.g = g;
    }

    /**
     * Returns the DSA modulus (p).
     *
     * @return the DSA modulus
     */
    public BigInteger getP() {
        return p;
    }

    /**
     * Returns the DSA subgroup order (q).
     *
     * @return the DSA subgroup order
     */
    public BigInteger getQ() {
        return q;
    }

    /**
     * Returns the DSA generator (g).
     *
     * @return the DSA generator
     */
    public BigInteger getG() {
        return g;
    }

    /**
     * Returns the size of group elements in bits.
     *
     * @return the bit length of the modulus p
     */
    @Override
    public int getElementSizeBits() {
        return p.bitLength();
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
     * Returns the cyclic group associated with these DSA parameters.
     *
     * @return a DsaGroup instance with these parameters
     */
    @Override
    public CyclicGroup<BigInteger> getGroup() {
        return new DsaGroup(this);
    }

    /**
     * Returns a hash code value for this DsaParameters instance.
     *
     * @return a hash code value
     */
    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((p == null) ? 0 : p.hashCode());
        result = prime * result + ((q == null) ? 0 : q.hashCode());
        result = prime * result + ((g == null) ? 0 : g.hashCode());
        return result;
    }

    /**
     * Indicates whether some other object is "equal to" this one.
     *
     * @param obj the reference object with which to compare
     * @return true if this object is the same as the obj argument; false otherwise
     */
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
