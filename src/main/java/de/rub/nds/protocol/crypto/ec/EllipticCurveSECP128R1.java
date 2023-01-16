/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.protocol.crypto.ec;

import java.math.BigInteger;

@SuppressWarnings("SpellCheckingInspection")
public class EllipticCurveSECP128R1 extends EllipticCurveOverFp {

    public EllipticCurveSECP128R1() {
        super(new BigInteger("FFFFFFFDFFFFFFFFFFFFFFFFFFFFFFFC", 16), 
                new BigInteger("E87579C11079F43DD824993C2CEE5ED3", 16), 
                new BigInteger("FFFFFFFDFFFFFFFFFFFFFFFFFFFFFFFF", 16),
                new BigInteger("161FF7528B899B2D0C28607CA52C5B86", 16),
                new BigInteger("CF5AC8395BAFEB13C02DA292DDED7A83", 16),
                new BigInteger("FFFFFFFE0000000075A30D1B9038A115", 16));
    }
}
