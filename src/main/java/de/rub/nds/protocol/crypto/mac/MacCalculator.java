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

public class MacCalculator {

    private MacCalculator() {}

    public static byte[] compute(byte[] key, byte[] toMac, MacAlgorithm algorithm) {
        if (algorithm == MacAlgorithm.NONE) {
            return toMac;
        } else {
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
