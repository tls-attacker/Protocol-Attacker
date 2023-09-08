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
public class EllipticCurveSECP112R1 extends EllipticCurveOverFp {

    public EllipticCurveSECP112R1() {
        super(
                new BigInteger("DB7C2ABF62E35E668076BEAD2088", 16),
                new BigInteger("659EF8BA043916EEDE8911702B22", 16),
                new BigInteger("DB7C2ABF62E35E668076BEAD208B", 16),
                new BigInteger("09487239995A5EE76B55F9C2F098", 16),
                new BigInteger("A89CE5AF8724C0A23E0E0FF77500", 16),
                new BigInteger("DB7C2ABF62E35E7628DFAC6561C5", 16));
    }
}
