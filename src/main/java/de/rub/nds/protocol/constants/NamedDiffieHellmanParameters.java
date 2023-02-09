/*
 * Protocol-Attacker - A framework to create protocol analysis tools
 *
 * Copyright 2023-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.protocol.constants;

public enum NamedDiffieHellmanParameters implements GroupParameters {
    FFDHE2048(2048),
    FFDHE3072(3072),
    FFDHE4096(4096),
    FFDHE6144(6144),
    FFDHE8192(8192);

    private int bitLength;

    private NamedDiffieHellmanParameters(int bitLength) {
        this.bitLength = bitLength;
    }

    @Override
    public int getElementSize() {
        return bitLength;
    }
}
