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

public class EllipticCurveBrainpoolP256T1 extends EllipticCurveOverFp {
    @SuppressWarnings("SpellCheckingInspection")
    public EllipticCurveBrainpoolP256T1() {
        super(
                new BigInteger(
                        "a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5374", 16),
                new BigInteger(
                        "662c61c430d84ea4fe66a7733d0b76b7bf93ebc4af2f49256ae58101fee92b04", 16),
                new BigInteger(
                        "a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5377", 16),
                new BigInteger(
                        "a3e8eb3cc1cfe7b7732213b23a656149afa142c47aafbc2b79a191562e1305f4", 16),
                new BigInteger(
                        "2d996c823439c56d7f7b22e14644417e69bcb6de39d027001dabe8f35b25c9be", 16),
                new BigInteger(
                        "a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a7", 16));
    }
}
