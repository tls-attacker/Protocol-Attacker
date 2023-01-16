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
public class EllipticCurveSECT113R1 extends EllipticCurveOverF2m {

    public EllipticCurveSECT113R1() {
        super(  new BigInteger("003088250CA6E7C7FE649CE85820F7", 16),
                new BigInteger("00E8BEE4D3E2260744188BE0E9C723", 16),
                new BigInteger("020000000000000000000000000201", 16),
                new BigInteger("009D73616F35F4AB1407D73562C10F", 16),
                new BigInteger("00A52830277958EE84D1315ED31886", 16),
                new BigInteger("0100000000000000D9CCEC8A39E56F", 16));
    }
}
