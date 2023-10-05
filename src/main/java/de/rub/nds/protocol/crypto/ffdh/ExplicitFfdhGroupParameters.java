/*
 * Protocol-Attacker - A Framework to create Protocol Analysis Tools
 *
 * Copyright 2023-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.protocol.crypto.ffdh;

import de.rub.nds.protocol.constants.FfdhGroupParameters;
import java.math.BigInteger;

public class ExplicitFfdhGroupParameters extends FfdhGroupParameters {

    private BigInteger generator;
    private BigInteger modulus;

    public ExplicitFfdhGroupParameters(BigInteger generator, BigInteger modulus) {
        super(generator, modulus);
    }

    @Override
    public BigInteger getModulus() {
        return modulus;
    }

    @Override
    public BigInteger getGenerator() {
        return generator;
    }

    @Override
    public int getElementSizeBits() {
        return modulus.bitLength();
    }

    @Override
    public int getElementSizeBytes() {
        return (int) Math.ceil(((double) getElementSizeBits()) / 8);
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((modulus == null) ? 0 : modulus.hashCode());
        result = prime * result + ((generator == null) ? 0 : generator.hashCode());
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (obj == null) return false;
        if (getClass() != obj.getClass()) return false;
        ExplicitFfdhGroupParameters other = (ExplicitFfdhGroupParameters) obj;
        if (modulus == null) {
            if (other.modulus != null) return false;
        } else if (!modulus.equals(other.modulus)) return false;
        if (generator == null) {
            if (other.generator != null) return false;
        } else if (!generator.equals(other.generator)) return false;
        return true;
    }
}
