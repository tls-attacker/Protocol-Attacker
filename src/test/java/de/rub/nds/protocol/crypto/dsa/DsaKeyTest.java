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

    private ExplicitDsaParameters dsaParams;
    private DsaPrivateKey privateKey;
    private DsaPublicKey publicKey;

    @BeforeAll
    static void setup() {
        Security.addProvider(new BouncyCastleProvider());
    }

    @BeforeEach
    void setUp() {
        dsaParams =
                new ExplicitDsaParameters(
                        new BigInteger(
                                "86F4A2491234567890ABCDEFFEDCBA09876543211234567890ABCDEF87654321",
                                16),
                        new BigInteger(
                                "F7E1A085D69B3DDE54321FEDCBA9876543210FEDCBA9876543210FEDCBA98765",
                                16),
                        new BigInteger(
                                "6789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456",
                                16));

        // Create a private key with DSA parameters
        BigInteger x = new BigInteger("123456789");
        BigInteger k = new BigInteger("987654321");
        privateKey = new DsaPrivateKey(x, k, dsaParams);

        // Create a public key with Y = g^x mod p
        BigInteger y = dsaParams.getG().modPow(x, dsaParams.getP());
        publicKey = new DsaPublicKey(y, dsaParams);
    }

    @Test
    void testDsaKeyParameters() {
        assertEquals(dsaParams.getP(), privateKey.getModulus());
        assertEquals(dsaParams.getG(), privateKey.getGenerator());
        assertEquals(dsaParams.getQ(), privateKey.getQ());

        assertEquals(dsaParams.getP(), publicKey.getModulus());
        assertEquals(dsaParams.getG(), publicKey.getGenerator());
        assertEquals(dsaParams.getQ(), publicKey.getQ());
    }

    @Test
    void testParameterChange() {
        // Change parameters
        dsaParams =
                new ExplicitDsaParameters(
                        new BigInteger("123"), new BigInteger("456"), new BigInteger("789"));

        privateKey.setDsaParameters(dsaParams);
        publicKey.setDsaParameters(dsaParams);

        assertEquals(dsaParams.getP(), privateKey.getModulus());
        assertEquals(dsaParams.getG(), privateKey.getGenerator());
        assertEquals(dsaParams.getQ(), privateKey.getQ());

        assertEquals(dsaParams.getP(), publicKey.getModulus());
        assertEquals(dsaParams.getG(), publicKey.getGenerator());
        assertEquals(dsaParams.getQ(), publicKey.getQ());
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
