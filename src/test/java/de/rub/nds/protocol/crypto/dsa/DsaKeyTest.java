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
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.rub.nds.protocol.constants.HashAlgorithm;
import de.rub.nds.protocol.crypto.key.DsaPrivateKey;
import de.rub.nds.protocol.crypto.key.DsaPublicKey;
import de.rub.nds.protocol.crypto.signature.DsaSignatureComputations;
import de.rub.nds.protocol.crypto.signature.SignatureCalculator;
import java.math.BigInteger;
import java.security.Security;
import java.security.Signature;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class DsaKeyTest {

    private FipsDsaGroup1024_160 dsaParams1024;
    private FipsDsaGroup2048_256 dsaParams2048;
    private DsaPrivateKey privateKey;
    private DsaPublicKey publicKey;

    @BeforeAll
    static void setup() {
        Security.addProvider(new BouncyCastleProvider());
    }

    @BeforeEach
    void setUp() {
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
    void testDsaKeyParameters() {
        assertEquals(dsaParams1024.getP(), privateKey.getModulus());
        assertEquals(dsaParams1024.getG(), privateKey.getGenerator());
        assertEquals(dsaParams1024.getQ(), privateKey.getQ());

        assertEquals(dsaParams1024.getP(), publicKey.getModulus());
        assertEquals(dsaParams1024.getG(), publicKey.getGenerator());
        assertEquals(dsaParams1024.getQ(), publicKey.getQ());
    }

    @Test
    void testParameterChange() {
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

    @Test
    void testSignatureInteroperability() throws Exception {
        // This test verifies that:
        // 1. JSSE can verify signatures created by our implementation
        // 2. Our implementation can compute valid signatures

        // Generate a DSA key pair using Java security with default parameters
        java.security.KeyPairGenerator keyGen = java.security.KeyPairGenerator.getInstance("DSA");
        keyGen.initialize(1024);
        java.security.KeyPair keyPair = keyGen.generateKeyPair();

        // Get the JSSE private and public keys
        java.security.interfaces.DSAPrivateKey jssePrivateKey =
                (java.security.interfaces.DSAPrivateKey) keyPair.getPrivate();
        java.security.interfaces.DSAPublicKey jssePublicKey =
                (java.security.interfaces.DSAPublicKey) keyPair.getPublic();

        // Create equivalent keys using our DSA parameter implementation
        BigInteger x = jssePrivateKey.getX();
        BigInteger k = new BigInteger("987654321"); // Nonce for our implementation

        ExplicitDsaParameters customDsaParams =
                new ExplicitDsaParameters(
                        jssePrivateKey.getParams().getP(),
                        jssePrivateKey.getParams().getQ(),
                        jssePrivateKey.getParams().getG());

        DsaPrivateKey ourPrivateKey = new DsaPrivateKey(x, k, customDsaParams);

        // Data to sign
        byte[] dataToSign = "DSA interoperability test data".getBytes();

        // PART 1: Sign with JSSE to confirm key validity

        // Sign with JSSE
        Signature jsseSig = Signature.getInstance("SHA1withDSA");
        jsseSig.initSign(jssePrivateKey);
        jsseSig.update(dataToSign);
        byte[] jsseSignature = jsseSig.sign();

        // Verify the JSSE signature with JSSE (sanity check)
        jsseSig.initVerify(jssePublicKey);
        jsseSig.update(dataToSign);
        boolean jsseVerifiedJsseSignature = jsseSig.verify(jsseSignature);
        assertTrue(jsseVerifiedJsseSignature, "JSSE should verify its own signature");

        // PART 2: Sign with our implementation, verify with JSSE

        // Sign with our implementation
        DsaSignatureComputations computations = new DsaSignatureComputations();
        SignatureCalculator calculator = new SignatureCalculator();

        // Compute signature using our implementation
        calculator.computeDsaSignature(computations, ourPrivateKey, dataToSign, HashAlgorithm.SHA1);

        byte[] ourSignature = computations.getSignatureBytes().getValue();

        // Verify that our signature is valid according to our implementation
        assertTrue(
                computations.getSignatureValid(),
                "Our signature should be valid in our computations");

        // Verify our signature with JSSE
        jsseSig.initVerify(jssePublicKey);
        jsseSig.update(dataToSign);
        boolean jsseVerifiedOurSignature = jsseSig.verify(ourSignature);
        assertTrue(jsseVerifiedOurSignature, "JSSE should verify our signature");
    }
}
