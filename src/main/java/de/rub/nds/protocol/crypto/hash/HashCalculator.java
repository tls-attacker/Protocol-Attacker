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
        switch (algorithm) {
            case NONE:
                return toHash;
            case MD5:
                return computeMd5(toHash);
            case SHA1:
                return computeSha1(toHash);
            case SHA224:
                return computeHash(toHash, "SHA-224");
            case SHA256:
                return computeSha256(toHash);
            case SHA384:
                return computeSha384(toHash);
            case SHA512:
                return computeSha512(toHash);
            case SHA512_224:
                return computeHash(toHash, "SHA-512/224");
            case SHA512_256:
                return computeHash(toHash, "SHA-512/256");
            case SHA3_256:
                return computeHash(toHash, "SHA3-256");
            default:
                throw new UnsupportedOperationException(
                        "Hash function not implemented: " + algorithm.name());
        }
    }

    public static byte[] computeMd5(byte[] toHash) {
        return computeHash(toHash, "MD5");
    }

    public static byte[] computeSha1(byte[] toHash) {
        return computeHash(toHash, "SHA1");
    }

    public static byte[] computeSha256(byte[] toHash) {
        return computeHash(toHash, "SHA256");
    }

    public static byte[] computeSha384(byte[] toHash) {
        return computeHash(toHash, "SHA384");
    }

    public static byte[] computeSha512(byte[] toHash) {
        return computeHash(toHash, "SHA512");
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
