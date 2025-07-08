/*
 * Protocol-Attacker - A Framework to create Protocol Analysis Tools
 *
 * Copyright 2023-2024 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.protocol.crypto.mac;

import de.rub.nds.protocol.constants.MacAlgorithm;
import de.rub.nds.protocol.exception.CryptoException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Utility class for computing Message Authentication Codes (MACs) using standard algorithms. If the key is zero-length,
 * it returns a zeroed MAC of the specified length. If the algorithm is NONE, it returns the original data.
 */
public class MacCalculator {

    private static final Logger LOGGER = LogManager.getLogger();

    private MacCalculator() {}

    /**
     * Computes a Message Authentication Code (MAC) for the given data using the specified
     * algorithm.
     *
     * @param key the secret key to use for MAC computation
     * @param toMac the data to compute the MAC for
     * @param algorithm the MAC algorithm to use
     * @return the computed MAC value, or the original data if algorithm is NONE
     * @throws CryptoException if the MAC algorithm is not supported or key is invalid
     */
    public static byte[] compute(byte[] key, byte[] toMac, MacAlgorithm algorithm) {
        if (algorithm == MacAlgorithm.NONE) {
            return toMac;
        } else {
            if (key.length == 0) {
                // TODO #71 Ideally we return a proper MAC, but the Java implementation does not
                // allow
                // this.
                LOGGER.warn("Key length is zero, returning empty MAC");
                return new byte[algorithm.getMacLength()];
            }
            return computeMac(key, toMac, algorithm.getJavaName());
        }
    }

    private static byte[] computeMac(byte[] key, byte[] toMac, String javaName) {

        try {
            Mac mac = Mac.getInstance(javaName);
            mac.init(new SecretKeySpec(key, mac.getAlgorithm()));
            mac.update(toMac);
            return mac.doFinal();
        } catch (NoSuchAlgorithmException | InvalidKeyException ex) {
            throw new CryptoException("Unknown mac algorithm: " + javaName, ex);
        }
    }
}
