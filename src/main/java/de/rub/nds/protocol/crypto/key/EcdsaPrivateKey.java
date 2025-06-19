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

public class EcdsaPrivateKey implements PrivateKeyContainer {

    private BigInteger privateKey;

    private BigInteger nonce;

    private NamedEllipticCurveParameters parameters;

    /** Default constructor for deserialization. */
    @SuppressWarnings("unused")
    private EcdsaPrivateKey() {
        this.privateKey = null;
        this.nonce = null;
        this.parameters = null;
    }

    /**
     * Constructs an ECDSA private key with the specified private key value, nonce, and curve
     * parameters.
     *
     * @param privateKey the private key value
     * @param nonce the nonce value used in ECDSA signatures
     * @param parameters the elliptic curve parameters
     */
    public EcdsaPrivateKey(
            BigInteger privateKey, BigInteger nonce, NamedEllipticCurveParameters parameters) {
        this.privateKey = privateKey;
        this.parameters = parameters;
        this.nonce = nonce;
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

    /**
     * Gets the nonce value used in ECDSA signatures.
     *
     * @return the nonce value
     */
    public BigInteger getNonce() {
        return nonce;
    }
}
