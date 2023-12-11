/*
 * Protocol-Attacker - A Framework to create Protocol Analysis Tools
 *
 * Copyright 2023-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.protocol.crypto.key;

import de.rub.nds.protocol.constants.AsymmetricAlgorithmType;
import de.rub.nds.protocol.constants.FfdhGroupParameters;
import de.rub.nds.protocol.crypto.ffdh.ExplicitFfdhGroupParameters;
import java.math.BigInteger;

public class DhPublicKey implements PublicKeyContainer {

    private FfdhGroupParameters parameters;

    private BigInteger publicKey;

    public DhPublicKey(BigInteger publicKey, BigInteger generator, BigInteger modulus) {
        this.parameters = new ExplicitFfdhGroupParameters(generator, modulus);
        this.publicKey = publicKey;
    }

    public DhPublicKey(BigInteger publicKey, FfdhGroupParameters parameters) {
        this.parameters = parameters;
        this.publicKey = publicKey;
    }

    public BigInteger getModulus() {
        return parameters.getModulus();
    }

    public BigInteger getGenerator() {
        return parameters.getGenerator();
    }

    public BigInteger getPublicKey() {
        return publicKey;
    }

    @Override
    public int length() {
        return getModulus().bitLength();
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((parameters == null) ? 0 : parameters.hashCode());
        result = prime * result + ((publicKey == null) ? 0 : publicKey.hashCode());
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (obj == null) return false;
        if (getClass() != obj.getClass()) return false;
        DhPublicKey other = (DhPublicKey) obj;
        if (parameters == null) {
            if (other.parameters != null) return false;
        } else if (!parameters.equals(other.parameters)) return false;
        if (publicKey == null) {
            if (other.publicKey != null) return false;
        } else if (!publicKey.equals(other.publicKey)) return false;
        return true;
    }

    @Override
    public AsymmetricAlgorithmType getAlgorithmType() {
        return AsymmetricAlgorithmType.DH;
    }
}
