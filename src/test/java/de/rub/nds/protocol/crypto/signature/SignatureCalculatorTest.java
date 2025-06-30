/*
 * Protocol-Attacker - A Framework to create Protocol Analysis Tools
 *
 * Copyright 2023-2024 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.protocol.crypto.signature;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.rub.nds.modifiablevariable.util.DataConverter;
import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.protocol.constants.HashAlgorithm;
import de.rub.nds.protocol.constants.NamedEllipticCurveParameters;
import de.rub.nds.protocol.constants.SignatureAlgorithm;
import de.rub.nds.protocol.crypto.key.DsaPrivateKey;
import de.rub.nds.protocol.crypto.key.EcdsaPrivateKey;
import de.rub.nds.protocol.crypto.key.RsaPrivateKey;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.KeySpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.security.spec.RSAPublicKeySpec;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

class SignatureCalculatorTest {

    private static final Logger LOGGER = LogManager.getLogger();

    @BeforeAll
    static void setup() {
        Security.addProvider(new BouncyCastleProvider());
    }

    /** Test of computeRsaPkcs1Signature method, of class SignatureCalculator. */
    @Test
    void testComputeRsaPkcs1Signature() {
        RsaPkcs1SignatureComputations computations = new RsaPkcs1SignatureComputations();
        BigInteger modulus =
                new BigInteger(
                        1,
                        DataConverter.hexStringToByteArray(
                                "00cbfb45e6b09f1af40df60ddc865b6f98a1fd724678b583bfb5ae8539627bffdcd930d7c3f996f75e15172a017f143101ecd28fc629b800e24f0a83665d77c0a3"));
        BigInteger privateKey =
                new BigInteger(
                        1,
                        DataConverter.hexStringToByteArray(
                                "61a4eb153f3f2a9be18303a7a8f964366074fe9b15756e97fad48c19a8374b870589dde72e4377f3837ab59fa76b55563642f2df635da71a3aa50ab835201b61"));
        byte[] toBeSignedBytes = "abcdefghijklmnopqrstuvwxyz\n".getBytes();
        HashAlgorithm hashAlgorithm = HashAlgorithm.SHA1;
        SignatureCalculator instance = new SignatureCalculator();
        instance.computeRsaPkcs1Signature(
                computations,
                new RsaPrivateKey(privateKey, modulus),
                toBeSignedBytes,
                hashAlgorithm);
        assertArrayEquals(toBeSignedBytes, computations.getToBeSignedBytes().getValue());

        assertArrayEquals(
                DataConverter.hexStringToByteArray("8c723a0fa70b111017b4a6f06afe1c0dbcec14e3"),
                computations.getDigestBytes().getValue());
        assertArrayEquals(
                DataConverter.hexStringToByteArray(
                        "3021300906052b0e03021a050004148c723a0fa70b111017b4a6f06afe1c0dbcec14e3"),
                computations.getDerEncodedDigest().getValue());

        assertEquals(HashAlgorithm.SHA1, computations.getHashAlgorithm());
        assertArrayEquals(
                DataConverter.hexStringToByteArray(
                        "0001ffffffffffffffffffffffffffffffffffffffffffffffffffff00"),
                computations.getPadding().getValue());
        assertArrayEquals(
                DataConverter.hexStringToByteArray(
                        "0001ffffffffffffffffffffffffffffffffffffffffffffffffffff003021300906052b0e03021a050004148c723a0fa70b111017b4a6f06afe1c0dbcec14e3"),
                computations.getPlainToBeSigned().getValue());
        assertArrayEquals(
                DataConverter.hexStringToByteArray(
                        "9139be98f16cf53d22da63cb559bb06a93338da6a344e28a4285c2da33facb7080d26e7a09483779a016eebc207602fc3f90492c2f2fb8143f0fe30fd855593d"),
                computations.getSignatureBytes().getValue());
        assertArrayEquals(toBeSignedBytes, computations.getToBeSignedBytes().getValue());
        assertEquals(modulus, computations.getModulus().getValue());
        assertEquals(privateKey, computations.getPrivateKey().getValue());
        assertTrue(computations.getSignatureValid());
    }

    /**
     * Test of computeDsaSignature method, of class SignatureCalculator.
     *
     * @throws SignatureException
     * @throws InvalidKeyException
     * @throws NoSuchAlgorithmException
     */
    @Test
    void testComputeDsaSignature() throws Exception {
        DsaSignatureComputations computations = new DsaSignatureComputations();
        BigInteger privateKey =
                new BigInteger(
                        1,
                        DataConverter.hexStringToByteArray(
                                "D0EC4E50BB290A42E9E355C73D8809345DE2E139"));
        byte[] toBeSignedBytes = DataConverter.hexStringToByteArray("616263");
        BigInteger nonce =
                new BigInteger(
                        1,
                        DataConverter.hexStringToByteArray(
                                "349C55648DCF992F3F33E8026CFAC87C1D2BA075"));
        BigInteger q =
                new BigInteger(
                        1,
                        DataConverter.hexStringToByteArray(
                                "E950511EAB424B9A19A2AEB4E159B7844C589C4F"));
        BigInteger g =
                new BigInteger(
                        1,
                        DataConverter.hexStringToByteArray(
                                "D29D5121B0423C2769AB21843E5A3240FF19CACC792264E3BB6BE4F78EDD1B15C4DFF7F1D905431F0AB16790E1F773B5CE01C804E509066A9919F5195F4ABC58189FD9FF987389CB5BEDF21B4DAB4F8B76A055FFE2770988FE2EC2DE11AD92219F0B351869AC24DA3D7BA87011A701CE8EE7BFE49486ED4527B7186CA4610A75"));
        BigInteger p =
                new BigInteger(
                        1,
                        DataConverter.hexStringToByteArray(
                                "E0A67598CD1B763BC98C8ABB333E5DDA0CD3AA0E5E1FB5BA8A7B4EABC10BA338FAE06DD4B90FDA70D7CF0CB0C638BE3341BEC0AF8A7330A3307DED2299A0EE606DF035177A239C34A912C202AA5F83B9C4A7CF0235B5316BFC6EFB9A248411258B30B839AF172440F32563056CB67A861158DDD90E6A894C72A5BBEF9E286C6B"));
        HashAlgorithm hashAlgorithm = HashAlgorithm.SHA1;
        SignatureCalculator instance = new SignatureCalculator();
        instance.computeDsaSignature(
                computations,
                new DsaPrivateKey(q, privateKey, nonce, g, p),
                toBeSignedBytes,
                hashAlgorithm);
        // Generate public key
        KeySpec pubKeySpec = new DSAPublicKeySpec(g.modPow(privateKey, p), p, q, g);
        KeyFactory keyFactory = KeyFactory.getInstance("DSA");
        PublicKey pubKey = keyFactory.generatePublic(pubKeySpec);

        // Initialize signature object
        Signature sig = Signature.getInstance("SHA1withDSA");
        sig.initVerify(pubKey);

        // Update and verify the signature
        sig.update(computations.getToBeSignedBytes().getValue());
        boolean verified = sig.verify(computations.getSignatureBytes().getValue());
        assertTrue(verified);
        assertEquals(
                new BigInteger(
                        1,
                        DataConverter.hexStringToByteArray(
                                "D29D5121B0423C2769AB21843E5A3240FF19CACC792264E3BB6BE4F78EDD1B15C4DFF7F1D905431F0AB16790E1F773B5CE01C804E509066A9919F5195F4ABC58189FD9FF987389CB5BEDF21B4DAB4F8B76A055FFE2770988FE2EC2DE11AD92219F0B351869AC24DA3D7BA87011A701CE8EE7BFE49486ED4527B7186CA4610A75")),
                computations.getG().getValue());
        assertEquals(
                new BigInteger(
                        1,
                        DataConverter.hexStringToByteArray(
                                "D557A1B4E7346C4A55427A28D47191381C269BDE")),
                computations.getInverseNonce().getValue());
        assertEquals(
                new BigInteger(
                        1,
                        DataConverter.hexStringToByteArray(
                                "349C55648DCF992F3F33E8026CFAC87C1D2BA075")),
                computations.getNonce().getValue());
        assertEquals(
                new BigInteger(
                        1,
                        DataConverter.hexStringToByteArray(
                                "E0A67598CD1B763BC98C8ABB333E5DDA0CD3AA0E5E1FB5BA8A7B4EABC10BA338FAE06DD4B90FDA70D7CF0CB0C638BE3341BEC0AF8A7330A3307DED2299A0EE606DF035177A239C34A912C202AA5F83B9C4A7CF0235B5316BFC6EFB9A248411258B30B839AF172440F32563056CB67A861158DDD90E6A894C72A5BBEF9E286C6B")),
                computations.getP().getValue());
        assertEquals(
                new BigInteger(
                        1,
                        DataConverter.hexStringToByteArray(
                                "D0EC4E50BB290A42E9E355C73D8809345DE2E139")),
                computations.getPrivateKey().getValue());
        assertEquals(
                new BigInteger(
                        1,
                        DataConverter.hexStringToByteArray(
                                "E950511EAB424B9A19A2AEB4E159B7844C589C4F")),
                computations.getQ().getValue());
        assertEquals(
                new BigInteger(
                        1,
                        DataConverter.hexStringToByteArray(
                                "636155AC9A4633B4665D179F9E4117DF68601F34")),
                computations.getR().getValue());
        assertEquals(
                new BigInteger(
                        1,
                        DataConverter.hexStringToByteArray(
                                "6C540B02D9D4852F89DF8CFC99963204F4347704")),
                computations.getS().getValue());
        assertTrue(computations.getSignatureValid());
        assertArrayEquals(
                DataConverter.hexStringToByteArray(
                        "302C0214636155AC9A4633B4665D179F9E4117DF68601F3402146C540B02D9D4852F89DF8CFC99963204F4347704"),
                computations.getSignatureBytes().getValue());
        assertArrayEquals(
                DataConverter.hexStringToByteArray("616263"),
                computations.getToBeSignedBytes().getValue());
        assertArrayEquals(
                DataConverter.hexStringToByteArray("A9993E364706816ABA3E25717850C26C9CD0D89D"),
                computations.getTruncatedHashBytes().getValue());
        assertEquals(
                new BigInteger(
                        1,
                        DataConverter.hexStringToByteArray(
                                "5D69A2B1B6988FFA5FA41AFAE8526C15535D7B35")),
                computations.getXr().getValue());
    }

    /** Test of computeEcdsaSignature method, of class SignatureCalculator. */
    @Test
    void testComputeEcdsaSignature() {
        EcdsaSignatureComputations computations = new EcdsaSignatureComputations();

        BigInteger privateKey =
                new BigInteger(
                        1,
                        DataConverter.hexStringToByteArray(
                                "519b423d715f8b581f4fa8ee59f4771a5b44c8130b4e3eacca54a56dda72b464"));
        byte[] toBeSignedBytes =
                DataConverter.hexStringToByteArray(
                        "44acf6b7e36c1342c2c5897204fe09504e1e2efb1a900377dbc4e7a6a133ec56");
        computations.setDigestBytes(Modifiable.explicit(toBeSignedBytes));
        computations.setTruncatedHashBytes(
                Modifiable.explicit(
                        toBeSignedBytes)); // The test message is already hashed, so we have to
        // cheat a little
        BigInteger nonce =
                new BigInteger(
                        1,
                        DataConverter.hexStringToByteArray(
                                "94a1bbb14b906a61a280f245f9e93c7f3b4a6247824f5d33b9670787642a68de"));
        NamedEllipticCurveParameters ecParameters = NamedEllipticCurveParameters.SECP256R1;
        HashAlgorithm hashAlgorithm = HashAlgorithm.SHA256;
        SignatureCalculator instance = new SignatureCalculator();
        instance.computeEcdsaSignature(
                computations,
                new EcdsaPrivateKey(privateKey, nonce, ecParameters),
                toBeSignedBytes,
                hashAlgorithm);

        assertEquals(NamedEllipticCurveParameters.SECP256R1, computations.getEcParameters());
        assertEquals(HashAlgorithm.SHA256, computations.getHashAlgorithm());
        assertEquals(
                new BigInteger(
                        1,
                        DataConverter.hexStringToByteArray(
                                "94a1bbb14b906a61a280f245f9e93c7f3b4a6247824f5d33b9670787642a68de")),
                computations.getNonce().getValue());
        assertEquals(
                new BigInteger(
                        1,
                        DataConverter.hexStringToByteArray(
                                "519b423d715f8b581f4fa8ee59f4771a5b44c8130b4e3eacca54a56dda72b464")),
                computations.getPrivateKey().getValue());

        assertArrayEquals(
                DataConverter.hexStringToByteArray(
                        "44acf6b7e36c1342c2c5897204fe09504e1e2efb1a900377dbc4e7a6a133ec56"),
                computations.getToBeSignedBytes().getValue());
        assertEquals(
                new BigInteger(
                        1,
                        DataConverter.hexStringToByteArray(
                                "44acf6b7e36c1342c2c5897204fe09504e1e2efb1a900377dbc4e7a6a133ec56")),
                computations.getTruncatedHash().getValue());
        assertArrayEquals(
                DataConverter.hexStringToByteArray(
                        "44acf6b7e36c1342c2c5897204fe09504e1e2efb1a900377dbc4e7a6a133ec56"),
                computations.getTruncatedHashBytes().getValue());
        assertEquals(
                new BigInteger(
                        1,
                        DataConverter.hexStringToByteArray(
                                "f3ac8061b514795b8843e3d6629527ed2afd6b1f6a555a7acabb5e6f79c8c2ac")),
                computations.getR().getValue());
        assertEquals(
                new BigInteger(
                        1,
                        DataConverter.hexStringToByteArray(
                                "8bf77819ca05a6b2786c76262bf7371cef97b218e96f175a3ccdda2acc058903")),
                computations.getS().getValue());
        assertTrue(computations.getSignatureValid());
    }

    @Test
    void testRsaSsaPssSignatureComputation() throws Exception {
        byte[] originalData = "test".getBytes();
        SignatureCalculator signatureCalculator = new SignatureCalculator();
        RsaSsaPssSignatureComputations computations = new RsaSsaPssSignatureComputations();
        BigInteger modulus =
                new BigInteger(
                        1,
                        DataConverter.hexStringToByteArray(
                                "00cbfb45e6b09f1af40df60ddc865b6f98a1fd724678b583bfb5ae8539627bffdcd930d7c3f996f75e15172a017f143101ecd28fc629b800e24f0a83665d77c0a3"));
        BigInteger privateKey =
                new BigInteger(
                        1,
                        DataConverter.hexStringToByteArray(
                                "61a4eb153f3f2a9be18303a7a8f964366074fe9b15756e97fad48c19a8374b870589dde72e4377f3837ab59fa76b55563642f2df635da71a3aa50ab835201b61"));
        BigInteger publicExponent = new BigInteger("65537");
        RsaPrivateKey rsaPrivateKey = new RsaPrivateKey(privateKey, modulus);
        computations.setSalt(new byte[] {01, 02});
        signatureCalculator.computeRsaPssSignature(
                computations,
                rsaPrivateKey,
                originalData,
                HashAlgorithm.SHA256,
                computations.getSalt().getValue());
        // Generate the public key

        LOGGER.debug("Signature: {}", computations.getSignatureBytes().getValue());

        Signature signature = Signature.getInstance("SHA256withRSA/PSS");
        MGF1ParameterSpec mgf1ParameterSpec = new MGF1ParameterSpec("SHA-256");
        PSSParameterSpec pssParameterSpec =
                new PSSParameterSpec("SHA-256", "MGF1", mgf1ParameterSpec, 2, 1);
        signature.setParameter(pssParameterSpec);
        RSAPublicKeySpec spec2 = new RSAPublicKeySpec(modulus, publicExponent);
        KeyFactory factory = KeyFactory.getInstance("RSA");
        PublicKey pubKey = factory.generatePublic(spec2);
        signature.initVerify(pubKey);

        // Update the data to be verified and verify the signature
        signature.update(originalData);
        boolean isSignatureValid = signature.verify(computations.getSignatureBytes().getValue());
        assertTrue(isSignatureValid);
    }

    @Test
    void testCreateSignatureComputations() {
        SignatureCalculator calculator = new SignatureCalculator();

        // Test RSA-PKCS1
        SignatureComputations rsaPkcs1 =
                calculator.createSignatureComputations(SignatureAlgorithm.RSA_PKCS1);
        assertTrue(rsaPkcs1 instanceof RsaPkcs1SignatureComputations);

        // Test RSA-PSS
        SignatureComputations rsaPss =
                calculator.createSignatureComputations(SignatureAlgorithm.RSA_SSA_PSS);
        assertTrue(rsaPss instanceof RsaSsaPssSignatureComputations);

        // Test DSA
        SignatureComputations dsa = calculator.createSignatureComputations(SignatureAlgorithm.DSA);
        assertTrue(dsa instanceof DsaSignatureComputations);

        // Test ECDSA
        SignatureComputations ecdsa =
                calculator.createSignatureComputations(SignatureAlgorithm.ECDSA);
        assertTrue(ecdsa instanceof EcdsaSignatureComputations);

        // Test EdDSA
        SignatureComputations ed25519 =
                calculator.createSignatureComputations(SignatureAlgorithm.ED25519);
        assertTrue(ed25519 instanceof EddsaSignatureComputations);

        SignatureComputations ed448 =
                calculator.createSignatureComputations(SignatureAlgorithm.ED448);
        assertTrue(ed448 instanceof EddsaSignatureComputations);

        // Test GOST
        SignatureComputations gost1 =
                calculator.createSignatureComputations(SignatureAlgorithm.GOSTR34102001);
        assertTrue(gost1 instanceof GostSignatureComputations);

        SignatureComputations gost256 =
                calculator.createSignatureComputations(SignatureAlgorithm.GOSTR34102012_256);
        assertTrue(gost256 instanceof GostSignatureComputations);

        SignatureComputations gost512 =
                calculator.createSignatureComputations(SignatureAlgorithm.GOSTR34102012_512);
        assertTrue(gost512 instanceof GostSignatureComputations);

        // Test null
        SignatureComputations noSig = calculator.createSignatureComputations(null);
        assertTrue(noSig instanceof NoSignatureComputations);
    }

    @Test
    void testComputeSignatureWithWrongKeyType() {
        SignatureCalculator calculator = new SignatureCalculator();

        // Test RSA computations with wrong key type
        RsaPkcs1SignatureComputations rsaComputations = new RsaPkcs1SignatureComputations();
        DsaPrivateKey dsaKey =
                new DsaPrivateKey(
                        new BigInteger("123"),
                        new BigInteger("456"),
                        new BigInteger("789"),
                        new BigInteger("111"),
                        new BigInteger("222"));

        assertThrows(
                IllegalArgumentException.class,
                () ->
                        calculator.computeSignature(
                                rsaComputations,
                                dsaKey,
                                "test".getBytes(),
                                SignatureAlgorithm.RSA_PKCS1,
                                HashAlgorithm.SHA256));

        // Test DSA computations with wrong key type
        DsaSignatureComputations dsaComputations = new DsaSignatureComputations();
        RsaPrivateKey rsaKey = new RsaPrivateKey(new BigInteger("123"), new BigInteger("456"));

        assertThrows(
                IllegalArgumentException.class,
                () ->
                        calculator.computeSignature(
                                dsaComputations,
                                rsaKey,
                                "test".getBytes(),
                                SignatureAlgorithm.DSA,
                                HashAlgorithm.SHA256));

        // Test ECDSA computations with wrong key type
        EcdsaSignatureComputations ecdsaComputations = new EcdsaSignatureComputations();

        assertThrows(
                IllegalArgumentException.class,
                () ->
                        calculator.computeSignature(
                                ecdsaComputations,
                                rsaKey,
                                "test".getBytes(),
                                SignatureAlgorithm.ECDSA,
                                HashAlgorithm.SHA256));
    }

    @ParameterizedTest
    @EnumSource(
            value = HashAlgorithm.class,
            names = {"MD5", "SHA1", "SHA224", "SHA256", "SHA384", "SHA512"})
    void testRsaPkcs1WithDifferentHashAlgorithms(HashAlgorithm hashAlgorithm) throws Exception {
        // Generate RSA key pair
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        var keyPair = keyGen.generateKeyPair();
        RSAPrivateKey privKey = (RSAPrivateKey) keyPair.getPrivate();
        RSAPublicKey pubKey = (RSAPublicKey) keyPair.getPublic();

        RsaPrivateKey protocolPrivKey =
                new RsaPrivateKey(privKey.getPrivateExponent(), privKey.getModulus());

        byte[] message = "Test message for different hash algorithms".getBytes();

        SignatureCalculator calculator = new SignatureCalculator();
        RsaPkcs1SignatureComputations computations = new RsaPkcs1SignatureComputations();

        calculator.computeRsaPkcs1Signature(computations, protocolPrivKey, message, hashAlgorithm);

        // Verify with BouncyCastle
        String signatureAlgo = hashAlgorithm.getJavaName() + "withRSA";
        Signature verifier = Signature.getInstance(signatureAlgo);
        verifier.initVerify(pubKey);
        verifier.update(message);

        assertTrue(verifier.verify(computations.getSignatureBytes().getValue()));
    }

    @Test
    void testRsaPkcs1WithEmptyMessage() throws Exception {
        SignatureCalculator calculator = new SignatureCalculator();
        RsaPkcs1SignatureComputations computations = new RsaPkcs1SignatureComputations();

        BigInteger modulus =
                new BigInteger(
                        1,
                        DataConverter.hexStringToByteArray(
                                "00cbfb45e6b09f1af40df60ddc865b6f98a1fd724678b583bfb5ae8539627bffdcd930d7c3f996f75e15172a017f143101ecd28fc629b800e24f0a83665d77c0a3"));
        BigInteger privateKey =
                new BigInteger(
                        1,
                        DataConverter.hexStringToByteArray(
                                "61a4eb153f3f2a9be18303a7a8f964366074fe9b15756e97fad48c19a8374b870589dde72e4377f3837ab59fa76b55563642f2df635da71a3aa50ab835201b61"));

        RsaPrivateKey rsaPrivateKey = new RsaPrivateKey(privateKey, modulus);
        byte[] emptyMessage = new byte[0];

        calculator.computeRsaPkcs1Signature(
                computations, rsaPrivateKey, emptyMessage, HashAlgorithm.SHA256);

        assertNotNull(computations.getSignatureBytes().getValue());
        assertTrue(computations.getSignatureValid());

        // Verify with BouncyCastle
        BigInteger publicExponent = new BigInteger("65537");
        RSAPublicKeySpec pubKeySpec = new RSAPublicKeySpec(modulus, publicExponent);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey pubKey = keyFactory.generatePublic(pubKeySpec);

        Signature verifier = Signature.getInstance("SHA256withRSA");
        verifier.initVerify(pubKey);
        verifier.update(emptyMessage);

        assertTrue(verifier.verify(computations.getSignatureBytes().getValue()));
    }

    @Test
    void testRsaPkcs1WithLargeMessage() throws Exception {
        SignatureCalculator calculator = new SignatureCalculator();
        RsaPkcs1SignatureComputations computations = new RsaPkcs1SignatureComputations();

        // Generate RSA key pair
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        var keyPair = keyGen.generateKeyPair();
        RSAPrivateKey privKey = (RSAPrivateKey) keyPair.getPrivate();
        RSAPublicKey pubKey = (RSAPublicKey) keyPair.getPublic();

        RsaPrivateKey protocolPrivKey =
                new RsaPrivateKey(privKey.getPrivateExponent(), privKey.getModulus());

        // Create a large message (10KB)
        byte[] largeMessage = new byte[10 * 1024];
        new SecureRandom().nextBytes(largeMessage);

        calculator.computeRsaPkcs1Signature(
                computations, protocolPrivKey, largeMessage, HashAlgorithm.SHA256);

        assertNotNull(computations.getSignatureBytes().getValue());
        assertTrue(computations.getSignatureValid());

        // Verify with BouncyCastle
        Signature verifier = Signature.getInstance("SHA256withRSA");
        verifier.initVerify(pubKey);
        verifier.update(largeMessage);

        assertTrue(verifier.verify(computations.getSignatureBytes().getValue()));
    }

    @Test
    void testRsaPkcs1WithHashAlgorithmNone() {
        SignatureCalculator calculator = new SignatureCalculator();
        RsaPkcs1SignatureComputations computations = new RsaPkcs1SignatureComputations();

        BigInteger modulus =
                new BigInteger(
                        1,
                        DataConverter.hexStringToByteArray(
                                "00cbfb45e6b09f1af40df60ddc865b6f98a1fd724678b583bfb5ae8539627bffdcd930d7c3f996f75e15172a017f143101ecd28fc629b800e24f0a83665d77c0a3"));
        BigInteger privateKey =
                new BigInteger(
                        1,
                        DataConverter.hexStringToByteArray(
                                "61a4eb153f3f2a9be18303a7a8f964366074fe9b15756e97fad48c19a8374b870589dde72e4377f3837ab59fa76b55563642f2df635da71a3aa50ab835201b61"));

        RsaPrivateKey rsaPrivateKey = new RsaPrivateKey(privateKey, modulus);
        byte[] message = "Test message without hashing".getBytes();

        calculator.computeRsaPkcs1Signature(
                computations, rsaPrivateKey, message, HashAlgorithm.NONE);

        assertNotNull(computations.getSignatureBytes().getValue());
        assertTrue(computations.getSignatureValid());
        // With NONE hash algorithm, the message itself is used as digest
        assertArrayEquals(message, computations.getDigestBytes().getValue());
        assertArrayEquals(message, computations.getDerEncodedDigest().getValue());
    }

    @ParameterizedTest
    @EnumSource(
            value = HashAlgorithm.class,
            names = {"SHA256", "SHA384", "SHA512"})
    void testRsaPssWithDifferentHashAlgorithms(HashAlgorithm hashAlgorithm) throws Exception {
        // Generate RSA key pair
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        var keyPair = keyGen.generateKeyPair();
        RSAPrivateKey privKey = (RSAPrivateKey) keyPair.getPrivate();
        RSAPublicKey pubKey = (RSAPublicKey) keyPair.getPublic();

        RsaPrivateKey protocolPrivKey =
                new RsaPrivateKey(privKey.getPrivateExponent(), privKey.getModulus());

        byte[] message = "Test message for PSS with different hash algorithms".getBytes();
        // Use a reasonable salt length (typically same as hash length, but ensure it fits)
        int saltLength = Math.min(hashAlgorithm.getBitLength() / 8, 20);
        byte[] salt = new byte[saltLength];
        new SecureRandom().nextBytes(salt);

        SignatureCalculator calculator = new SignatureCalculator();
        RsaSsaPssSignatureComputations computations = new RsaSsaPssSignatureComputations();
        computations.setSalt(salt);

        calculator.computeRsaPssSignature(
                computations, protocolPrivKey, message, hashAlgorithm, salt);

        // Verify with BouncyCastle
        Signature verifier = Signature.getInstance("RSASSA-PSS");
        MGF1ParameterSpec mgf1Spec = new MGF1ParameterSpec(hashAlgorithm.getJavaName());
        PSSParameterSpec pssSpec =
                new PSSParameterSpec(hashAlgorithm.getJavaName(), "MGF1", mgf1Spec, saltLength, 1);
        verifier.setParameter(pssSpec);
        verifier.initVerify(pubKey);
        verifier.update(message);

        assertTrue(verifier.verify(computations.getSignatureBytes().getValue()));
    }

    @Test
    void testRsaPssWithoutSalt() {
        SignatureCalculator calculator = new SignatureCalculator();
        RsaSsaPssSignatureComputations computations = new RsaSsaPssSignatureComputations();

        BigInteger modulus = new BigInteger("12345");
        BigInteger privateKey = new BigInteger("67890");
        RsaPrivateKey rsaPrivateKey = new RsaPrivateKey(privateKey, modulus);

        // Don't set salt - should throw exception
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        calculator.computeSignature(
                                computations,
                                rsaPrivateKey,
                                "test".getBytes(),
                                SignatureAlgorithm.RSA_SSA_PSS,
                                HashAlgorithm.SHA256));
    }

    @Test
    void testDsaWithEmptyMessage() throws Exception {
        SignatureCalculator calculator = new SignatureCalculator();
        DsaSignatureComputations computations = new DsaSignatureComputations();

        // Generate DSA parameters
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA");
        keyGen.initialize(1024);
        var keyPair = keyGen.generateKeyPair();
        DSAPrivateKey privKey = (DSAPrivateKey) keyPair.getPrivate();
        DSAPublicKey pubKey = (DSAPublicKey) keyPair.getPublic();

        BigInteger nonce = new BigInteger(159, new SecureRandom());
        DsaPrivateKey protocolPrivKey =
                new DsaPrivateKey(
                        privKey.getParams().getQ(),
                        privKey.getX(),
                        nonce,
                        privKey.getParams().getG(),
                        privKey.getParams().getP());

        byte[] emptyMessage = new byte[0];

        calculator.computeDsaSignature(
                computations, protocolPrivKey, emptyMessage, HashAlgorithm.SHA1);

        assertNotNull(computations.getSignatureBytes().getValue());
        assertTrue(computations.getSignatureValid());

        // Verify with Java crypto
        Signature verifier = Signature.getInstance("SHA1withDSA");
        verifier.initVerify(pubKey);
        verifier.update(emptyMessage);

        assertTrue(verifier.verify(computations.getSignatureBytes().getValue()));
    }

    @Test
    void testEcdsaWithDifferentCurves() throws Exception {
        NamedEllipticCurveParameters[] curves = {
            NamedEllipticCurveParameters.SECP256R1,
            NamedEllipticCurveParameters.SECP384R1,
            NamedEllipticCurveParameters.SECP521R1
        };

        for (NamedEllipticCurveParameters curve : curves) {
            SignatureCalculator calculator = new SignatureCalculator();
            EcdsaSignatureComputations computations = new EcdsaSignatureComputations();

            // Generate ECDSA key pair for the curve
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
            ECGenParameterSpec ecSpec = new ECGenParameterSpec(curve.name().toLowerCase());
            keyGen.initialize(ecSpec);
            var keyPair = keyGen.generateKeyPair();
            ECPrivateKey privKey = (ECPrivateKey) keyPair.getPrivate();
            ECPublicKey pubKey = (ECPublicKey) keyPair.getPublic();

            BigInteger nonce =
                    new BigInteger(
                            curve.getGroup().getBasePointOrder().bitLength() - 1,
                            new SecureRandom());
            EcdsaPrivateKey protocolPrivKey = new EcdsaPrivateKey(privKey.getS(), nonce, curve);

            byte[] message = ("Test message for curve " + curve.name()).getBytes();

            calculator.computeEcdsaSignature(
                    computations, protocolPrivKey, message, HashAlgorithm.SHA256);

            assertNotNull(computations.getSignatureBytes().getValue());
            assertTrue(computations.getSignatureValid());

            // Verify with BouncyCastle
            Signature verifier = Signature.getInstance("SHA256withECDSA");
            verifier.initVerify(pubKey);
            verifier.update(message);

            assertTrue(
                    verifier.verify(computations.getSignatureBytes().getValue()),
                    "Failed to verify signature for curve " + curve.name());
        }
    }

    @Test
    void testComputeRawEcdsaSignature() {
        SignatureCalculator calculator = new SignatureCalculator();
        EcdsaSignatureComputations computations = new EcdsaSignatureComputations();

        BigInteger privateKey =
                new BigInteger(
                        1,
                        DataConverter.hexStringToByteArray(
                                "519b423d715f8b581f4fa8ee59f4771a5b44c8130b4e3eacca54a56dda72b464"));
        BigInteger nonce =
                new BigInteger(
                        1,
                        DataConverter.hexStringToByteArray(
                                "94a1bbb14b906a61a280f245f9e93c7f3b4a6247824f5d33b9670787642a68de"));
        NamedEllipticCurveParameters ecParameters = NamedEllipticCurveParameters.SECP256R1;

        EcdsaPrivateKey protocolPrivKey = new EcdsaPrivateKey(privateKey, nonce, ecParameters);
        byte[] message = "Test raw ECDSA signature".getBytes();

        calculator.computeRawEcdsaSignature(
                computations, protocolPrivKey, message, HashAlgorithm.SHA256);

        assertNotNull(computations.getSignatureBytes().getValue());
        assertTrue(computations.getSignatureValid());
        // Raw ECDSA signature should be exactly 64 bytes for SECP256R1 (32 bytes r + 32 bytes s)
        assertEquals(64, computations.getSignatureBytes().getValue().length);
    }

    @Test
    void testComputeSignatureWithGostAlgorithm() {
        SignatureCalculator calculator = new SignatureCalculator();
        GostSignatureComputations computations = new GostSignatureComputations();
        RsaPrivateKey dummyKey = new RsaPrivateKey(new BigInteger("123"), new BigInteger("456"));

        assertThrows(
                UnsupportedOperationException.class,
                () ->
                        calculator.computeSignature(
                                computations,
                                dummyKey,
                                "test".getBytes(),
                                SignatureAlgorithm.GOSTR34102001,
                                HashAlgorithm.SHA256));
    }

    @Test
    void testComputeSignatureWithNoSignatureComputations() {
        SignatureCalculator calculator = new SignatureCalculator();
        NoSignatureComputations computations = new NoSignatureComputations();
        RsaPrivateKey dummyKey = new RsaPrivateKey(new BigInteger("123"), new BigInteger("456"));

        // Should not throw exception, just do nothing
        calculator.computeSignature(
                computations,
                dummyKey,
                "test".getBytes(),
                SignatureAlgorithm.RSA_PKCS1,
                HashAlgorithm.SHA256);
    }

    @Test
    void testInverseNonceCalculationInEcdsa() {
        SignatureCalculator calculator = new SignatureCalculator();
        EcdsaSignatureComputations computations = new EcdsaSignatureComputations();

        BigInteger privateKey =
                new BigInteger(
                        1,
                        DataConverter.hexStringToByteArray(
                                "519b423d715f8b581f4fa8ee59f4771a5b44c8130b4e3eacca54a56dda72b464"));
        byte[] toBeSignedBytes =
                DataConverter.hexStringToByteArray(
                        "44acf6b7e36c1342c2c5897204fe09504e1e2efb1a900377dbc4e7a6a133ec56");
        computations.setDigestBytes(Modifiable.explicit(toBeSignedBytes));
        computations.setTruncatedHashBytes(Modifiable.explicit(toBeSignedBytes));
        BigInteger nonce =
                new BigInteger(
                        1,
                        DataConverter.hexStringToByteArray(
                                "94a1bbb14b906a61a280f245f9e93c7f3b4a6247824f5d33b9670787642a68de"));
        NamedEllipticCurveParameters ecParameters = NamedEllipticCurveParameters.SECP256R1;

        // First computation uses nonce for inverse calculation
        calculator.computeEcdsaSignature(
                computations,
                new EcdsaPrivateKey(privateKey, nonce, ecParameters),
                toBeSignedBytes,
                HashAlgorithm.SHA256);

        BigInteger firstInverseNonce = computations.getInverseNonce().getValue();

        // Verify that inverseNonce * nonce = 1 (mod order)
        BigInteger order = ecParameters.getGroup().getBasePointOrder();
        BigInteger product = firstInverseNonce.multiply(nonce).mod(order);
        assertEquals(BigInteger.ONE, product);

        // Second computation with computeRawEcdsaSignature uses privateKey for inverse
        EcdsaSignatureComputations computations2 = new EcdsaSignatureComputations();
        computations2.setDigestBytes(Modifiable.explicit(toBeSignedBytes));
        computations2.setTruncatedHashBytes(Modifiable.explicit(toBeSignedBytes));

        calculator.computeRawEcdsaSignature(
                computations2,
                new EcdsaPrivateKey(privateKey, nonce, ecParameters),
                toBeSignedBytes,
                HashAlgorithm.SHA256);

        BigInteger secondInverseNonce = computations2.getInverseNonce().getValue();

        // Verify that inverseNonce * privateKey = 1 (mod order)
        BigInteger product2 = secondInverseNonce.multiply(privateKey).mod(order);
        assertEquals(BigInteger.ONE, product2);
    }
}
