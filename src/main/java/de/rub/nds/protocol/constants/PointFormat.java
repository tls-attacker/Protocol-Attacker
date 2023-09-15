/*
 * Protocol-Attacker - A Framework to create Protocol Analysis Tools
 *
 * Copyright 2023-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.protocol.constants;

public enum PointFormat {
    UNCOMPRESSED((byte) 0x04),
    ANSIX962_COMPRESSED_CHAR2((byte) 0x03),
    ANSIX962_COMPRESSED_PRIME((byte) 0x02);

    private final byte ansiX961formatIdentifier;

    private PointFormat(byte formatIdentifier) {
        this.ansiX961formatIdentifier = formatIdentifier;
    }

    public byte getAnsiX961formatIdentifier() {
        return ansiX961formatIdentifier;
    }
}
