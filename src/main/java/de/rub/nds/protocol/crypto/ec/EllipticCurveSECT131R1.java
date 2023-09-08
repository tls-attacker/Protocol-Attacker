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
public class EllipticCurveSECT131R1 extends EllipticCurveOverF2m {

    public EllipticCurveSECT131R1() {
        super(
                new BigInteger("07A11B09A76B562144418FF3FF8C2570B8", 16),
                new BigInteger("0217C05610884B63B9C6C7291678F9D341", 16),
                new BigInteger("080000000000000000000000000000010d", 16),
                new BigInteger("0081baf91fdf9833c40f9c181343638399", 16),
                new BigInteger("078c6e7ea38c001f73c8134b1b4ef9e150", 16),
                new BigInteger("0400000000000000023123953A9464B54D", 16));
    }
}
