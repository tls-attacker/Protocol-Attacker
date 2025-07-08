/*
 * Protocol-Attacker - A Framework to create Protocol Analysis Tools
 *
 * Copyright 2023-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.protocol.crypto.key;

import java.math.BigInteger;

/** Stores RSA private key components: private exponent and modulus. */
public class RsaPrivateKey implements PrivateKeyContainer {

    private BigInteger privateExponent;

    private BigInteger modulus;

    /** Default constructor for deserialization. */
    @SuppressWarnings("unused")
    private RsaPrivateKey() {
        this.privateExponent = null;
        this.modulus = null;
    }

    /**
     * Constructs an RSA private key with the specified private exponent and modulus.
     *
     * @param privateExponent the private exponent
     * @param modulus the modulus
     */
    public RsaPrivateKey(BigInteger privateExponent, BigInteger modulus) {
        this.privateExponent = privateExponent;
        this.modulus = modulus;
    }

    /**
     * Gets the private exponent.
     *
     * @return the private exponent
     */
    public BigInteger getPrivateExponent() {
        return privateExponent;
    }

    /**
     * Gets the modulus.
     *
     * @return the modulus
     */
    public BigInteger getModulus() {
        return modulus;
    }
}
