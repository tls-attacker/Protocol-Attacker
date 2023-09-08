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
public class EllipticCurveSECT113R2 extends EllipticCurveOverF2m {

    public EllipticCurveSECT113R2() {
        super(
                new BigInteger("00689918dbec7e5a0dd6dfc0aa55c7", 16),
                new BigInteger("0095e9a9ec9b297bd4bf36e059184f", 16),
                new BigInteger("020000000000000000000000000201", 16),
                new BigInteger("01a57a6a7b26ca5ef52fcdb8164797", 16),
                new BigInteger("00b3adc94ed1fe674c06e695baba1d", 16),
                new BigInteger("010000000000000108789B2496AF93", 16));
    }
}
