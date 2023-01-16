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

public class EllipticCurveBrainpoolP160R1 extends EllipticCurveOverFp {
    @SuppressWarnings("SpellCheckingInspection")
    public EllipticCurveBrainpoolP160R1() {
        super(new BigInteger("340e7be2a280eb74e2be61bada745d97e8f7c300", 16),
            new BigInteger("1e589a8595423412134faa2dbdec95c8d8675e58", 16),
            new BigInteger("e95e4a5f737059dc60dfc7ad95b3d8139515620f", 16),
            new BigInteger("bed5af16ea3f6a4f62938c4631eb5af7bdbcdbc3", 16),
            new BigInteger("1667cb477a1a8ec338f94741669c976316da6321", 16),
            new BigInteger("e95e4a5f737059dc60df5991d45029409e60fc09", 16));
    }
}
