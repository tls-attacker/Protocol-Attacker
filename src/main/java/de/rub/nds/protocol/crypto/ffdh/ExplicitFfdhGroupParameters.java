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

    public ExplicitFfdhGroupParameters(BigInteger generator, BigInteger modulus) {
        super(generator, modulus);
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((getModulus() == null) ? 0 : getModulus().hashCode());
        result = prime * result + ((getGenerator() == null) ? 0 : getGenerator().hashCode());
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (obj == null) return false;
        if (getClass() != obj.getClass()) return false;
        ExplicitFfdhGroupParameters other = (ExplicitFfdhGroupParameters) obj;
        if (getModulus() == null) {
            if (other.getModulus() != null) return false;
        } else if (!getModulus().equals(other.getModulus())) return false;
        if (getGenerator() == null) {
            if (other.getGenerator() != null) return false;
        } else if (!getGenerator().equals(other.getGenerator())) return false;
        return true;
    }
}
