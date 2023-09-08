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

public class EllipticCurveBrainpoolP160T1 extends EllipticCurveOverFp {
    @SuppressWarnings("SpellCheckingInspection")
    public EllipticCurveBrainpoolP160T1() {
        super(
                new BigInteger("e95e4a5f737059dc60dfc7ad95b3d8139515620c", 16),
                new BigInteger("7a556b6dae535b7b51ed2c4d7daa7a0b5c55f380", 16),
                new BigInteger("e95e4a5f737059dc60dfc7ad95b3d8139515620f", 16),
                new BigInteger("b199b13b9b34efc1397e64baeb05acc265ff2378", 16),
                new BigInteger("add6718b7c7c1961f0991b842443772152c9e0ad", 16),
                new BigInteger("e95e4a5f737059dc60df5991d45029409e60fc09", 16));
    }
}
