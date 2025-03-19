/*
 * Protocol-Attacker - A Framework to create Protocol Analysis Tools
 *
 * Copyright 2023-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.protocol.crypto.dsa;

import de.rub.nds.protocol.constants.DsaParameters;
import java.math.BigInteger;

public class ExplicitDsaParameters extends DsaParameters {

    public ExplicitDsaParameters(BigInteger p, BigInteger q, BigInteger g) {
        super(p, q, g);
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((getP() == null) ? 0 : getP().hashCode());
        result = prime * result + ((getQ() == null) ? 0 : getQ().hashCode());
        result = prime * result + ((getG() == null) ? 0 : getG().hashCode());
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (obj == null) return false;
        if (getClass() != obj.getClass()) return false;
        ExplicitDsaParameters other = (ExplicitDsaParameters) obj;
        if (getP() == null) {
            if (other.getP() != null) return false;
        } else if (!getP().equals(other.getP())) return false;
        if (getQ() == null) {
            if (other.getQ() != null) return false;
        } else if (!getQ().equals(other.getQ())) return false;
        if (getG() == null) {
            if (other.getG() != null) return false;
        } else if (!getG().equals(other.getG())) return false;
        return true;
    }
}
