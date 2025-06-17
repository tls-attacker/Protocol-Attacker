/*
 * Protocol-Attacker - A Framework to create Protocol Analysis Tools
 *
 * Copyright 2023-2024 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.protocol.crypto.key;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import org.junit.jupiter.api.Test;

class PrivateKeyContainerTest {

    @Test
    void testPrivateKeyContainerInterface() {
        // Use concrete implementations that require parameters
        BigInteger q = new BigInteger("11");
        BigInteger x = new BigInteger("3");
        BigInteger k = new BigInteger("7");
        BigInteger g = new BigInteger("2");
        BigInteger p = new BigInteger("23");
        BigInteger modulus = new BigInteger("123456789");
        BigInteger exponent = new BigInteger("65537");

        // Test concrete implementations implement the interface
        assertTrue(new DsaPrivateKey(q, x, k, g, p) instanceof PrivateKeyContainer);
        assertTrue(new RsaPrivateKey(exponent, modulus) instanceof PrivateKeyContainer);
    }
}
