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

public class EllipticCurveBrainpoolP192T1 extends EllipticCurveOverFp {
    @SuppressWarnings("SpellCheckingInspection")
    public EllipticCurveBrainpoolP192T1() {
        super(
                new BigInteger("c302f41d932a36cda7a3463093d18db78fce476de1a86294", 16),
                new BigInteger("13d56ffaec78681e68f9deb43b35bec2fb68542e27897b79", 16),
                new BigInteger("c302f41d932a36cda7a3463093d18db78fce476de1a86297", 16),
                new BigInteger("3ae9e58c82f63c30282e1fe7bbf43fa72c446af6f4618129", 16),
                new BigInteger("97e2c5667c2223a902ab5ca449d0084b7e5b3de7ccc01c9", 16),
                new BigInteger("c302f41d932a36cda7a3462f9e9e916b5be8f1029ac4acc1", 16));
    }
}
