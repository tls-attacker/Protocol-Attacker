/*
 * Protocol-Attacker - A Framework to create Protocol Analysis Tools
 *
 * Copyright 2023-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.protocol.crypto.ec;

import java.math.BigInteger;

@SuppressWarnings("SpellCheckingInspection")
public class EllipticCurveSECT131R2 extends EllipticCurveOverF2m {

    public EllipticCurveSECT131R2() {
        super(
                new BigInteger("03E5A88919D7CAFCBF415F07C2176573B2", 16),
                new BigInteger("04B8266A46C55657AC734CE38F018F2192", 16),
                new BigInteger("080000000000000000000000000000010d", 16),
                new BigInteger("0356dcd8f2f95031ad652d23951bb366a8", 16),
                new BigInteger("0648f06d867940a5366d9e265de9eb240f", 16),
                new BigInteger("0400000000000000016954A233049BA98F", 16));
    }
}
