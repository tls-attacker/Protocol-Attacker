/*
 * Protocol-Attacker - A Framework to create Protocol Analysis Tools
 *
 * Copyright 2023-2024 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.protocol.constants;

/**
 * Interface for hash algorithm implementations. Defines methods for retrieving algorithm properties
 * and computing hashes.
 */
public interface IHashAlgorithm {

    /**
     * Returns the output length of this hash algorithm in bits.
     *
     * @return the bit length of the hash output
     */
    int getBitLength();

    /**
     * Returns the security strength of this hash algorithm in bits.
     *
     * @return the security strength in bits
     */
    int getSecurityStrength();

    /**
     * Computes the hash of the given data.
     *
     * @param data the input data to hash
     * @return the computed hash value
     */
    byte[] computeHash(byte[] data);
}
