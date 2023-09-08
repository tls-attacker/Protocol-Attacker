/*
 * Protocol-Attacker - A framework to create protocol analysis tools
 *
 * Copyright 2023-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.protocol.crypto.ffdh;

import de.rub.nds.protocol.constants.FFDHGroupParameters;
import java.math.BigInteger;

public abstract class FFDHGroup implements FFDHGroupParameters {

    private final BigInteger generator;
    private final BigInteger modulus;

    public FFDHGroup(BigInteger generator, BigInteger modulus) {
        this.generator = generator;
        this.modulus = modulus;
    }

    @Override
    public BigInteger getGenerator() {
        return generator;
    }

    @Override
    public BigInteger getModulus() {
        return modulus;
    }

    @Override
    public int getElementSize() {
        return modulus.bitLength();
    }
}
