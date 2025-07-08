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

/**
 * DSA parameters with explicitly defined values rather than a named parameter set. Allows custom
 * DSA parameter configurations for non-standard implementations.
 */
public class ExplicitDsaParameters extends DsaParameters {

    /**
     * Create DSA parameters with explicit values
     *
     * @param p Modulus p
     * @param q Subgroup order q
     * @param g Generator g
     */
    public ExplicitDsaParameters(BigInteger p, BigInteger q, BigInteger g) {
        super(p, q, g);
    }
}
