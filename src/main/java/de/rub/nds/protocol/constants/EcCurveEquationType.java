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
 * Enumeration of elliptic curve equation types.
 * Defines the mathematical form of elliptic curves.
 */
public enum EcCurveEquationType {
    /** Curves in the form y² = x³ + ax + b. */
    SHORT_WEIERSTRASS,
    /** Curves in the form By² = x³ + Ax² + x. */
    MONTGOMERY,
    /** Curves in the form ax² + y² = 1 + dx²y². */
    EDWARDS
}
