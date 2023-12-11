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
public class EllipticCurveSECP160K1 extends EllipticCurveOverFp {
    public EllipticCurveSECP160K1() {
        super(
                BigInteger.ZERO,
                new BigInteger("7"),
                new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFAC73", 16),
                new BigInteger("3B4C382CE37AA192A4019E763036F4F5DD4D7EBB", 16),
                new BigInteger("938CF935318FDCED6BC28286531733C3F03C4FEE", 16),
                new BigInteger("0100000000000000000001B8FA16DFAB9ACA16B6B3", 16));
    }
}
