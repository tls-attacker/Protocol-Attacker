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

@SuppressWarnings("SpellCheckingInspection")
public class EllipticCurveSECP192R1 extends EllipticCurveOverFp {
    public EllipticCurveSECP192R1() {
        super(
                new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFC", 16),
                new BigInteger("64210519E59C80E70FA7E9AB72243049FEB8DEECC146B9B1", 16),
                new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF", 16),
                new BigInteger("188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012", 16),
                new BigInteger("07192B95FFC8DA78631011ED6B24CDD573F977A11E794811", 16),
                new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFF99DEF836146BC9B1B4D22831", 16));
    }
}
