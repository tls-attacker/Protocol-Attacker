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

class PublicKeyContainerTest {

    @Test
    void testPublicKeyContainerInterface() {
        // Use concrete implementations that require parameters
        BigInteger q = new BigInteger("11");
        BigInteger y = new BigInteger("9");
        BigInteger g = new BigInteger("2");
        BigInteger p = new BigInteger("23");
        BigInteger modulus = new BigInteger("123456789");
        BigInteger exponent = new BigInteger("65537");

        // Test concrete implementations implement the interface
        assertTrue(new DsaPublicKey(q, y, g, p) instanceof PublicKeyContainer);
        assertTrue(new RsaPublicKey(exponent, modulus) instanceof PublicKeyContainer);
    }
}
