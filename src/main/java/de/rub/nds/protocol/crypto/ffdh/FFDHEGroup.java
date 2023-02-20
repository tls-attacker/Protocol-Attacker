/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.protocol.crypto.ffdh;

import de.rub.nds.protocol.constants.GroupParameters;
import java.math.BigInteger;

public abstract class FFDHEGroup implements GroupParameters {

    private final BigInteger g;
    private final BigInteger p;

    public FFDHEGroup(BigInteger g, BigInteger p) {
        this.g = g;
        this.p = p;
    }

    public BigInteger getG() {
        return g;
    }

    public BigInteger getP() {
        return p;
    }

    @Override
    public int getElementSize() {
        return p.bitLength();
    }
}
