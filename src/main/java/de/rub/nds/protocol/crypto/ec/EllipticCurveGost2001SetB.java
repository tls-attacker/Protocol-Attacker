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

public class EllipticCurveGost2001SetB extends EllipticCurveOverFp {

    public EllipticCurveGost2001SetB() {
        super(
                new BigInteger(
                        "8000000000000000000000000000000000000000000000000000000000000C96", 16),
                new BigInteger(
                        "3E1AF419A269A5F866A7D3C25C3DF80AE979259373FF2B182F49D4CE7E1BBC8B", 16),
                new BigInteger(
                        "8000000000000000000000000000000000000000000000000000000000000C99", 16),
                BigInteger.ONE,
                new BigInteger(
                        "3FA8124359F96680B83D1C3EB2C070E5C545C9858D03ECFB744BF8D717717EFC", 16),
                new BigInteger(
                        "800000000000000000000000000000015F700CFFF1A624E5E497161BCC8A198F", 16));
    }
}
