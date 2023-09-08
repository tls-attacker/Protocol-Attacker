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
public class EllipticCurveSECP128R2 extends EllipticCurveOverFp {

    public EllipticCurveSECP128R2() {
        super(
                new BigInteger("D6031998D1B3BBFEBF59CC9BBFF9AEE1", 16),
                new BigInteger("5EEEFCA380D02919DC2C6558BB6D8A5D", 16),
                new BigInteger("FFFFFFFDFFFFFFFFFFFFFFFFFFFFFFFF", 16),
                new BigInteger("7B6AA5D85E572983E6FB32A7CDEBC140", 16),
                new BigInteger("27B6916A894D3AEE7106FE805FC34B44", 16),
                new BigInteger("3FFFFFFF7FFFFFFFBE0024720613B5A3", 16));
    }
}
