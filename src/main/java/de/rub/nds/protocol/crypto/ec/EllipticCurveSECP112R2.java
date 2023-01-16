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

@SuppressWarnings("SpellCheckingInspection")
public class EllipticCurveSECP112R2 extends EllipticCurveOverFp {

    public EllipticCurveSECP112R2() {
        super(new BigInteger("6127C24C05F38A0AAAF65C0EF02C", 16), 
                new BigInteger("51DEF1815DB5ED74FCC34C85D709", 16), 
                new BigInteger("DB7C2ABF62E35E668076BEAD208B", 16),
                new BigInteger("4BA30AB5E892B4E1649DD0928643", 16),
                new BigInteger("ADCD46F5882E3747DEF36E956E97", 16),
                new BigInteger("36DF0AAFD8B8D7597CA10520D04B", 16));
    }
}
