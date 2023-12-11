/*
 * Protocol-Attacker - A Framework to create Protocol Analysis Tools
 *
 * Copyright 2023-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.protocol.crypto.hash;

import de.rub.nds.protocol.constants.HashAlgorithm;
import de.rub.nds.protocol.exception.CryptoException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class HashCalculator {

    private HashCalculator() {}

    public static byte[] compute(byte[] toHash, HashAlgorithm algorithm) {
        if (algorithm == HashAlgorithm.NONE) {
            return toHash;
        } else {
            return computeHash(toHash, algorithm.getJavaName());
        }
    }

    private static byte[] computeHash(byte[] toHash, String algorithmName) {
        try {
            MessageDigest digest = MessageDigest.getInstance(algorithmName);
            return digest.digest(toHash);
        } catch (NoSuchAlgorithmException ex) {
            throw new CryptoException("Unknown hash algorithm: " + algorithmName, ex);
        }
    }
}
