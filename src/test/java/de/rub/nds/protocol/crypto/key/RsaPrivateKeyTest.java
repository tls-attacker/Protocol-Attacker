/*
 * Protocol-Attacker - A Framework to create Protocol Analysis Tools
 *
 * Copyright 2023-2024 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.protocol.crypto.key;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.math.BigInteger;
import org.junit.jupiter.api.Test;

class RsaPrivateKeyTest {

    // RsaPrivateKey doesn't have a default constructor

    @Test
    void testConstructorWithParameters() {
        // Create a key with parameters
        BigInteger privateExponent = new BigInteger("65537");
        BigInteger modulus = new BigInteger("12345678901234567890");

        RsaPrivateKey key = new RsaPrivateKey(privateExponent, modulus);

        // Verify parameters were set correctly
        assertEquals(privateExponent, key.getPrivateExponent());
        assertEquals(modulus, key.getModulus());
    }

    // RsaPrivateKey doesn't have setters
}
