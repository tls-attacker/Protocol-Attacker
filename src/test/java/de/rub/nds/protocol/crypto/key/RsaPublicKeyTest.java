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

class RsaPublicKeyTest {

    @Test
    void testConstructorWithParameters() {
        // Create a key with parameters
        BigInteger publicExponent = new BigInteger("65537");
        BigInteger modulus = new BigInteger("12345678901234567890");

        RsaPublicKey key = new RsaPublicKey(publicExponent, modulus);

        // Verify parameters were set correctly
        assertEquals(publicExponent, key.getPublicExponent());
        assertEquals(modulus, key.getModulus());
    }

    @Test
    void testSettersAndGetters() {
        // Create a key with parameters
        BigInteger initialExponent = new BigInteger("3");
        BigInteger initialModulus = new BigInteger("123456789");
        RsaPublicKey key = new RsaPublicKey(initialExponent, initialModulus);

        // Set new parameters
        BigInteger publicExponent = new BigInteger("65537");
        BigInteger modulus = new BigInteger("12345678901234567890");

        key.setPublicExponent(publicExponent);
        key.setModulus(modulus);

        // Verify parameters were set correctly
        assertEquals(publicExponent, key.getPublicExponent());
        assertEquals(modulus, key.getModulus());
    }
}
