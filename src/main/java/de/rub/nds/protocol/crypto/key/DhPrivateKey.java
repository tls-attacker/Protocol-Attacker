/*
 * Protocol-Attacker - A Framework to create Protocol Analysis Tools
 *
 * Copyright 2023-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.protocol.crypto.key;

import de.rub.nds.protocol.constants.FfdhGroupParameters;
import java.math.BigInteger;

/** Stores Diffie-Hellman private key and group parameters. */
public class DhPrivateKey implements PrivateKeyContainer {

    private BigInteger privateKey;

    private FfdhGroupParameters parameters;

    /** Default constructor for deserialization. */
    @SuppressWarnings("unused")
    private DhPrivateKey() {
        this.privateKey = null;
        this.parameters = null;
    }

    /**
     * Constructs a new DH private key with the specified private key value and group parameters.
     *
     * @param privateKey the private key value
     * @param parameters the FFDH group parameters
     */
    public DhPrivateKey(BigInteger privateKey, FfdhGroupParameters parameters) {
        this.privateKey = privateKey;
        this.parameters = parameters;
    }

    /**
     * Returns the private key value.
     *
     * @return the private key value
     */
    public BigInteger getPrivateKey() {
        return privateKey;
    }

    /**
     * Returns the FFDH group parameters associated with this private key.
     *
     * @return the FFDH group parameters
     */
    public FfdhGroupParameters getParameters() {
        return parameters;
    }
}
