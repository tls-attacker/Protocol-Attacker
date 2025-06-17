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

class DsaPrivateKeyTest {

    // DsaPrivateKey doesn't have a default constructor

    @Test
    void testConstructorWithParameters() {
        // Create a key with parameters
        BigInteger q = new BigInteger("11");
        BigInteger x = new BigInteger("3");
        BigInteger k = new BigInteger("7");
        BigInteger g = new BigInteger("2");
        BigInteger p = new BigInteger("23");

        DsaPrivateKey key = new DsaPrivateKey(q, x, k, g, p);

        // Verify parameters were set correctly
        assertEquals(q, key.getQ());
        assertEquals(x, key.getX());
        assertEquals(k, key.getK());
        assertEquals(g, key.getGenerator());
        assertEquals(p, key.getModulus());
    }

    @Test
    void testSettersAndGetters() {
        // Create a key with parameters
        BigInteger q = new BigInteger("11");
        BigInteger x = new BigInteger("3");
        BigInteger k = new BigInteger("7");
        BigInteger g = new BigInteger("2");
        BigInteger p = new BigInteger("23");

        DsaPrivateKey key = new DsaPrivateKey(q, x, k, g, p);

        // Test X and K setters only
        BigInteger newX = new BigInteger("5");
        BigInteger newK = new BigInteger("9");

        key.setX(newX);
        key.setK(newK);

        // Verify parameters were set correctly
        assertEquals(q, key.getQ());
        assertEquals(newX, key.getX()); // Updated
        assertEquals(newK, key.getK()); // Updated
        assertEquals(g, key.getGenerator());
        assertEquals(p, key.getModulus());
    }
}
