package de.rub.nds.protocol.crypto.hash;

import de.rub.nds.protocol.exception.CryptoException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Level;
import java.util.logging.Logger;

public class HashCalculator {

    private HashCalculator() {
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
