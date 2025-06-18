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
 * Enumeration of asymmetric cryptographic algorithm types. Distinguishes between different public
 * key cryptography families.
 */
public enum AsymmetricAlgorithmType {
    /** Rivest-Shamir-Adleman algorithm. */
    RSA,
    /** Elliptic Curve Digital Signature Algorithm. */
    ECDSA,
    /** Edwards-curve Digital Signature Algorithm. */
    EDDSA,
    /** Digital Signature Algorithm. */
    DSA,
    /** Diffie-Hellman key exchange. */
    DH,
    /** Elliptic Curve Diffie-Hellman. */
    ECDH,
}
