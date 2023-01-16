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

public class EllipticCurveBrainpoolP224T1 extends EllipticCurveOverFp {
    @SuppressWarnings("SpellCheckingInspection")
    public EllipticCurveBrainpoolP224T1() {
        super(new BigInteger("d7c134aa264366862a18302575d1d787b09f075797da89f57ec8c0fc", 16),
            new BigInteger("4b337d934104cd7bef271bf60ced1ed20da14c08b3bb64f18a60888d", 16),
            new BigInteger("d7c134aa264366862a18302575d1d787b09f075797da89f57ec8c0ff", 16),
            new BigInteger("6ab1e344ce25ff3896424e7ffe14762ecb49f8928ac0c76029b4d580", 16),
            new BigInteger("374e9f5143e568cd23f3f4d7c0d4b1e41c8cc0d1c6abd5f1a46db4c", 16),
            new BigInteger("d7c134aa264366862a18302575d0fb98d116bc4b6ddebca3a5a7939f", 16));
    }
}
