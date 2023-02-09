/*
 * Protocol-Attacker - A framework to create protocol analysis tools
 *
 * Copyright 2023-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.protocol.crypto.ec;

import java.math.BigInteger;

public class EllipticCurveBrainpoolP192R1 extends EllipticCurveOverFp {
    @SuppressWarnings("SpellCheckingInspection")
    public EllipticCurveBrainpoolP192R1() {
        super(
                new BigInteger("6a91174076b1e0e19c39c031fe8685c1cae040e5c69a28ef", 16),
                new BigInteger("469a28ef7c28cca3dc721d044f4496bcca7ef4146fbf25c9", 16),
                new BigInteger("c302f41d932a36cda7a3463093d18db78fce476de1a86297", 16),
                new BigInteger("c0a0647eaab6a48753b033c56cb0f0900a2f5c4853375fd6", 16),
                new BigInteger("14b690866abd5bb88b5f4828c1490002e6773fa2fa299b8f", 16),
                new BigInteger("c302f41d932a36cda7a3462f9e9e916b5be8f1029ac4acc1", 16));
    }
}
