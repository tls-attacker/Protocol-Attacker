/*
 * Protocol-Attacker - A Framework to create Protocol Analysis Tools
 *
 * Copyright 2023-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.protocol.crypto.key;

import de.rub.nds.protocol.constants.NamedEllipticCurveParameters;
import java.math.BigInteger;

public class EddsaPrivateKey implements PrivateKeyContainer {

    private BigInteger privateKey;

    private NamedEllipticCurveParameters parameters;

    /** Default constructor for deserialization. */
    @SuppressWarnings("unused")
    private EddsaPrivateKey() {
        this.privateKey = null;
        this.parameters = null;
    }

    /**
     * Constructs an EdDSA private key with the specified private key value and curve parameters.
     *
     * @param privateKey the private key value
     * @param parameters the elliptic curve parameters
     */
    public EddsaPrivateKey(BigInteger privateKey, NamedEllipticCurveParameters parameters) {
        this.privateKey = privateKey;
        this.parameters = parameters;
    }

    /**
     * Gets the private key value.
     *
     * @return the private key value
     */
    public BigInteger getPrivateKey() {
        return privateKey;
    }

    /**
     * Gets the elliptic curve parameters associated with this private key.
     *
     * @return the elliptic curve parameters
     */
    public NamedEllipticCurveParameters getParameters() {
        return parameters;
    }
}
