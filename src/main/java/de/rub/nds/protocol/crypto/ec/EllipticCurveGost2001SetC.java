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

public class EllipticCurveGost2001SetC extends EllipticCurveOverFp {

    public EllipticCurveGost2001SetC() {
        super(
                new BigInteger(
                        "9B9F605F5A858107AB1EC85E6B41C8AACF846E86789051D37998F7B9022D7598", 16),
                new BigInteger("805A", 16),
                new BigInteger(
                        "9B9F605F5A858107AB1EC85E6B41C8AACF846E86789051D37998F7B9022D759B", 16),
                BigInteger.ZERO,
                new BigInteger(
                        "41ECE55743711A8C3CBF3783CD08C0EE4D4DC440D4641A8F366E550DFDB3BB67", 16),
                new BigInteger(
                        "9B9F605F5A858107AB1EC85E6B41C8AA582CA3511EDDFB74F02F3A6598980BB9", 16));
    }
}
