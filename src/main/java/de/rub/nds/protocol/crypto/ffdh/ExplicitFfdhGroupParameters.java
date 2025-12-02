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

/**
 * Represents explicit finite field Diffie-Hellman group parameters where the generator and modulus
 * are explicitly specified rather than using predefined standard groups.
 */
public class ExplicitFfdhGroupParameters extends FfdhGroupParameters {

    /**
     * Constructs explicit FFDH group parameters with the specified generator and modulus.
     *
     * @param generator the generator element of the group
     * @param modulus the modulus (prime p) of the group
     */
    /** Default constructor for deserialization. */
    @SuppressWarnings("unused")
    private ExplicitFfdhGroupParameters() {
        super(null, null);
    }

    public ExplicitFfdhGroupParameters(BigInteger generator, BigInteger modulus) {
        super(generator, modulus);
    }

    /**
     * Computes the hash code for this ExplicitFfdhGroupParameters instance.
     *
     * @return the hash code based on the modulus and generator
     */
    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((getModulus() == null) ? 0 : getModulus().hashCode());
        result = prime * result + ((getGenerator() == null) ? 0 : getGenerator().hashCode());
        return result;
    }

    /**
     * Checks if this ExplicitFfdhGroupParameters instance is equal to another object.
     *
     * @param obj the object to compare with
     * @return true if the objects are equal, false otherwise
     */
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
