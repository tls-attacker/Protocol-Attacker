/*
 * Protocol-Attacker - A Framework to create Protocol Analysis Tools
 *
 * Copyright 2023-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.protocol.crypto.dsa;

import de.rub.nds.protocol.constants.DsaParameters;
import java.math.BigInteger;

/** DSA Parameters from FIPS 186-4, Appendix A.1. with L=1024, N=160 */
public class FipsDsaGroup1024_160 extends DsaParameters {

    // Standard DSA parameters L=1024, N=160 bits (FIPS 186-4)
    private static final String P_HEX =
            "800000000000000089e1855218a0e7dac38136ffafa72eda7"
                    + "859f2171e25e65eac698c1702578b07dc2a1076da241c76c6"
                    + "2d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebe"
                    + "ac04f48c3c84afb796d61e8e01";
    private static final String Q_HEX = "8ff962a92eef0ade8c576291a8d93d45fa181c76";
    private static final String G_HEX =
            "626d027839ea0a13413163a55b4cb500299d5522956cefcb"
                    + "3bff10f399ce2c2e71cb186724a41a6c1ce2160665e121305"
                    + "82fc626e3bcc721adb8643944dbd4f51f84f02b5c04bb8b43"
                    + "db43a9f2aba1da33a009a61b34d94148a7a5a834b248d";

    private static final BigInteger P = new BigInteger(P_HEX, 16);
    private static final BigInteger Q = new BigInteger(Q_HEX, 16);
    private static final BigInteger G = new BigInteger(G_HEX, 16);

    public FipsDsaGroup1024_160() {
        super(P, Q, G);
    }
}
