/*
 * Protocol-Attacker - A Framework to create Protocol Analysis Tools
 *
 * Copyright 2023-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.protocol.crypto.ec;

import com.fasterxml.jackson.annotation.JsonTypeInfo;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import java.io.Serializable;
import java.math.BigInteger;
import java.util.Objects;

/**
 * Abstract base class for finite field elements.
 *
 * <p>Represents immutable elements of finite fields used in elliptic curve cryptography. Subclasses
 * implement specific field arithmetic for prime fields (Fp) and binary fields (F2m). All operations
 * return new instances, preserving immutability.
 */
@XmlAccessorType(XmlAccessType.FIELD)
@JsonTypeInfo(use = JsonTypeInfo.Id.CLASS, include = JsonTypeInfo.As.PROPERTY, property = "@class")
public abstract class FieldElement implements Serializable {

    /*
     * FieldElement objects are immutable. This should make deep copies in the methods of the EllipticCurve class
     * unnecessary.
     */
    private final BigInteger data;
    private final BigInteger modulus;

    /** Default constructor for deserialization. */
    protected FieldElement() {
        this.data = null;
        this.modulus = null;
    }

    protected FieldElement(BigInteger data, BigInteger modulus) {
        this.data = data;
        this.modulus = modulus;
    }

    /**
     * Adds this element to another field element.
     *
     * @param f field element to add
     * @return this + f
     */
    public abstract FieldElement add(FieldElement f);

    /**
     * Subtracts another field element from this element.
     *
     * @param f field element to subtract
     * @return this - f
     */
    public FieldElement subtract(FieldElement f) {
        f = f.addInv();
        return add(f);
    }

    /**
     * Multiplies this element by another field element.
     *
     * @param f field element to multiply by
     * @return this * f
     */
    public abstract FieldElement mult(FieldElement f);

    /**
     * Divides this element by another field element.
     *
     * @param f field element to divide by (the multiplicative inverse must exist in the field)
     * @return this / f
     */
    public FieldElement divide(FieldElement f) {
        f = f.multInv();
        return mult(f);
    }

    /**
     * Computes the additive inverse of this element.
     *
     * @return -this such that this + (-this) = 0
     */
    public abstract FieldElement addInv();

    /**
     * Computes the multiplicative inverse of this element.
     *
     * @return this^-1 such that this * this^-1 = 1
     * @throws ArithmeticException if this is not invertible (e.g., if it is zero in the field)
     */
    public abstract FieldElement multInv();

    /**
     * Returns the data value of this field element.
     *
     * @return The data value as a BigInteger
     */
    public BigInteger getData() {
        return this.data;
    }

    /**
     * Returns the modulus of the field this element belongs to.
     *
     * @return The field modulus as a BigInteger
     */
    public BigInteger getModulus() {
        return this.modulus;
    }

    /** {@inheritDoc} */
    @Override
    public int hashCode() {
        int hash = 5;
        hash = 89 * hash + Objects.hashCode(this.data);
        hash = 89 * hash + Objects.hashCode(this.modulus);
        return hash;
    }

    /** {@inheritDoc} */
    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final FieldElement other = (FieldElement) obj;
        if (!Objects.equals(this.data, other.data)) {
            return false;
        }
        if (!Objects.equals(this.modulus, other.modulus)) {
            return false;
        }
        return true;
    }

    /** {@inheritDoc} */
    @Override
    public String toString() {
        return this.getData().toString() + " mod " + this.getModulus().toString();
    }
}
