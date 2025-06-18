/*
 * Protocol-Attacker - A Framework to create Protocol Analysis Tools
 *
 * Copyright 2023-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.protocol.crypto.ec;

import java.math.BigInteger;

/**
 * Represents an element of a prime field Fp.
 *
 * <p>Implements field arithmetic modulo a prime p. All operations are performed
 * using modular arithmetic to ensure results stay within the field.
 */
public class FieldElementFp extends FieldElement {

    /**
     * Instantiates the element data in the field F_modulus. With modulus being a prime number.
     *
     * @param data The value representing the field element
     * @param modulus The prime modulus defining the field
     */
    public FieldElementFp(BigInteger data, BigInteger modulus) {
        super(data.mod(modulus), modulus);
    }

    /** Default constructor for deserialization. */
    @SuppressWarnings("unused")
    private FieldElementFp() {
        super(null, null);
    }

    /** {@inheritDoc} */
    @Override
    public FieldElement add(FieldElement f) {
        BigInteger tmp = this.getData().add(f.getData());
        tmp = tmp.mod(this.getModulus());
        return new FieldElementFp(tmp, this.getModulus());
    }

    /** {@inheritDoc} */
    @Override
    public FieldElement mult(FieldElement f) {
        BigInteger tmp = this.getData().multiply(f.getData());
        tmp = tmp.mod(this.getModulus());
        return new FieldElementFp(tmp, this.getModulus());
    }

    /** {@inheritDoc} */
    @Override
    public FieldElement addInv() {
        BigInteger tmp = this.getData().negate();
        tmp = tmp.mod(this.getModulus());
        return new FieldElementFp(tmp, this.getModulus());
    }

    /** {@inheritDoc} */
    @Override
    public FieldElement multInv() {
        if (this.getData().equals(BigInteger.ZERO)) {
            throw new ArithmeticException();
        }
        BigInteger tmp = this.getData().modInverse(this.getModulus());
        return new FieldElementFp(tmp, this.getModulus());
    }
}
