/*
 * Protocol-Attacker - A Framework to create Protocol Analysis Tools
 *
 * Copyright 2023-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.protocol.constants;

/**
 * Enumeration of elliptic curve point representation formats.
 * Defines how points are encoded on elliptic curves.
 */
public enum PointFormat {
    /** Point represented with both x and y coordinates. */
    UNCOMPRESSED,
    /** Point represented with x coordinate and y sign bit. */
    COMPRESSED
}
