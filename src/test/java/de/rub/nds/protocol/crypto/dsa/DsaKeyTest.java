/*
 * Protocol-Attacker - A Framework to create Protocol Analysis Tools
 *
 * Copyright 2023-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.protocol.crypto.dsa;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import de.rub.nds.protocol.crypto.key.DsaPrivateKey;
import de.rub.nds.protocol.crypto.key.DsaPublicKey;
import java.math.BigInteger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class DsaKeyTest {

    private FipsDsaGroup1024_160 dsaParams1024;
    private FipsDsaGroup2048_256 dsaParams2048;
    private DsaPrivateKey privateKey;
    private DsaPublicKey publicKey;

    @BeforeEach
    public void setUp() {
        dsaParams1024 = new FipsDsaGroup1024_160();
        dsaParams2048 = new FipsDsaGroup2048_256();

        // Create a private key with DSA parameters
        BigInteger x = new BigInteger("123456789");
        BigInteger k = new BigInteger("987654321");
        privateKey = new DsaPrivateKey(x, k, dsaParams1024);

        // Create a public key with Y = g^x mod p
        BigInteger y = dsaParams1024.getG().modPow(x, dsaParams1024.getP());
        publicKey = new DsaPublicKey(y, dsaParams1024);
    }

    @Test
    public void testDsaKeyCreation() {
        assertNotNull(privateKey);
        assertNotNull(publicKey);
    }

    @Test
    public void testDsaKeyParameters() {
        assertEquals(dsaParams1024.getP(), privateKey.getModulus());
        assertEquals(dsaParams1024.getG(), privateKey.getGenerator());
        assertEquals(dsaParams1024.getQ(), privateKey.getQ());

        assertEquals(dsaParams1024.getP(), publicKey.getModulus());
        assertEquals(dsaParams1024.getG(), publicKey.getGenerator());
        assertEquals(dsaParams1024.getQ(), publicKey.getQ());
    }

    @Test
    public void testParameterChange() {
        // Change parameters
        privateKey.setDsaParameters(dsaParams2048);
        publicKey.setDsaParameters(dsaParams2048);

        assertEquals(dsaParams2048.getP(), privateKey.getModulus());
        assertEquals(dsaParams2048.getG(), privateKey.getGenerator());
        assertEquals(dsaParams2048.getQ(), privateKey.getQ());

        assertEquals(dsaParams2048.getP(), publicKey.getModulus());
        assertEquals(dsaParams2048.getG(), publicKey.getGenerator());
        assertEquals(dsaParams2048.getQ(), publicKey.getQ());
    }
}
