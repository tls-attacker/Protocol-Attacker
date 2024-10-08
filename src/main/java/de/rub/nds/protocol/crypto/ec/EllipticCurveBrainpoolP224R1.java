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

public class EllipticCurveBrainpoolP224R1 extends EllipticCurveOverFp {
    @SuppressWarnings("SpellCheckingInspection")
    public EllipticCurveBrainpoolP224R1() {
        super(
                new BigInteger("68a5e62ca9ce6c1c299803a6c1530b514e182ad8b0042a59cad29f43", 16),
                new BigInteger("2580f63ccfe44138870713b1a92369e33e2135d266dbb372386c400b", 16),
                new BigInteger("d7c134aa264366862a18302575d1d787b09f075797da89f57ec8c0ff", 16),
                new BigInteger("d9029ad2c7e5cf4340823b2a87dc68c9e4ce3174c1e6efdee12c07d", 16),
                new BigInteger("58aa56f772c0726f24c6b89e4ecdac24354b9e99caa3f6d3761402cd", 16),
                new BigInteger("d7c134aa264366862a18302575d0fb98d116bc4b6ddebca3a5a7939f", 16));
    }
}
