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

class DsaPublicKeyTest {

    // DsaPublicKey doesn't have a default constructor

    @Test
    void testConstructorWithParameters() {
        // Create a key with parameters
        BigInteger q = new BigInteger("11");
        BigInteger y = new BigInteger("9");
        BigInteger g = new BigInteger("2");
        BigInteger p = new BigInteger("23");

        DsaPublicKey key = new DsaPublicKey(q, y, g, p);

        // Verify parameters were set correctly
        assertEquals(q, key.getQ());
        assertEquals(y, key.getY());
        assertEquals(g, key.getGenerator());
        assertEquals(p, key.getModulus());
    }

    @Test
    void testSetY() {
        // Create a key with parameters
        BigInteger q = new BigInteger("11");
        BigInteger y = new BigInteger("9");
        BigInteger g = new BigInteger("2");
        BigInteger p = new BigInteger("23");

        DsaPublicKey key = new DsaPublicKey(q, y, g, p);

        // Test Y setter only
        BigInteger newY = new BigInteger("10");
        key.setY(newY);

        // Verify parameters were set correctly
        assertEquals(q, key.getQ());
        assertEquals(newY, key.getY()); // Updated
        assertEquals(g, key.getGenerator());
        assertEquals(p, key.getModulus());
    }
}
