/*
 * Protocol-Attacker - A Framework to create Protocol Analysis Tools
 *
 * Copyright 2023-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.protocol.crypto.signature;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.protocol.constants.HashAlgorithm;
import de.rub.nds.protocol.constants.NamedEllipticCurveParameters;
import de.rub.nds.protocol.crypto.key.DsaPrivateKey;
import de.rub.nds.protocol.crypto.key.EcdsaPrivateKey;
import de.rub.nds.protocol.crypto.key.RsaPrivateKey;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.KeySpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

public class SignatureCalculatorTest {

    @BeforeAll
    public static void setup() {
        Security.addProvider(new BouncyCastleProvider());
    }

    /** Test of computeRsaPkcs1Signature method, of class SignatureCalculator. */
    @Test
    public void testComputeRsaPkcs1Signature() {
        RsaPkcs1SignatureComputations computations = new RsaPkcs1SignatureComputations();
        BigInteger modulus =
                new BigInteger(
                        1,
                        ArrayConverter.hexStringToByteArray(
                                "00cbfb45e6b09f1af40df60ddc865b6f98a1fd724678b583bfb5ae8539627bffdcd930d7c3f996f75e15172a017f143101ecd28fc629b800e24f0a83665d77c0a3"));
        BigInteger privateKey =
                new BigInteger(
                        1,
                        ArrayConverter.hexStringToByteArray(
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
                ArrayConverter.hexStringToByteArray("8c723a0fa70b111017b4a6f06afe1c0dbcec14e3"),
                computations.getDigestBytes().getValue());
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray(
                        "3021300906052b0e03021a050004148c723a0fa70b111017b4a6f06afe1c0dbcec14e3"),
                computations.getDerEncodedDigest().getValue());

        assertEquals(HashAlgorithm.SHA1, computations.getHashAlgorithm());
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray(
                        "0001ffffffffffffffffffffffffffffffffffffffffffffffffffff00"),
                computations.getPadding().getValue());
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray(
                        "0001ffffffffffffffffffffffffffffffffffffffffffffffffffff003021300906052b0e03021a050004148c723a0fa70b111017b4a6f06afe1c0dbcec14e3"),
                computations.getPlainToBeSigned().getValue());
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray(
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
    public void testComputeDsaSignature() throws Exception {
        DsaSignatureComputations computations = new DsaSignatureComputations();
        BigInteger privateKey =
                new BigInteger(
                        1,
                        ArrayConverter.hexStringToByteArray(
                                "D0EC4E50BB290A42E9E355C73D8809345DE2E139"));
        byte[] toBeSignedBytes = ArrayConverter.hexStringToByteArray("616263");
        BigInteger nonce =
                new BigInteger(
                        1,
                        ArrayConverter.hexStringToByteArray(
                                "349C55648DCF992F3F33E8026CFAC87C1D2BA075"));
        BigInteger q =
                new BigInteger(
                        1,
                        ArrayConverter.hexStringToByteArray(
                                "E950511EAB424B9A19A2AEB4E159B7844C589C4F"));
        BigInteger g =
                new BigInteger(
                        1,
                        ArrayConverter.hexStringToByteArray(
                                "D29D5121B0423C2769AB21843E5A3240FF19CACC792264E3BB6BE4F78EDD1B15C4DFF7F1D905431F0AB16790E1F773B5CE01C804E509066A9919F5195F4ABC58189FD9FF987389CB5BEDF21B4DAB4F8B76A055FFE2770988FE2EC2DE11AD92219F0B351869AC24DA3D7BA87011A701CE8EE7BFE49486ED4527B7186CA4610A75"));
        BigInteger p =
                new BigInteger(
                        1,
                        ArrayConverter.hexStringToByteArray(
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
                        ArrayConverter.hexStringToByteArray(
                                "D29D5121B0423C2769AB21843E5A3240FF19CACC792264E3BB6BE4F78EDD1B15C4DFF7F1D905431F0AB16790E1F773B5CE01C804E509066A9919F5195F4ABC58189FD9FF987389CB5BEDF21B4DAB4F8B76A055FFE2770988FE2EC2DE11AD92219F0B351869AC24DA3D7BA87011A701CE8EE7BFE49486ED4527B7186CA4610A75")),
                computations.getG().getValue());
        assertEquals(
                new BigInteger(
                        1,
                        ArrayConverter.hexStringToByteArray(
                                "D557A1B4E7346C4A55427A28D47191381C269BDE")),
                computations.getInverseNonce().getValue());
        assertEquals(
                new BigInteger(
                        1,
                        ArrayConverter.hexStringToByteArray(
                                "349C55648DCF992F3F33E8026CFAC87C1D2BA075")),
                computations.getNonce().getValue());
        assertEquals(
                new BigInteger(
                        1,
                        ArrayConverter.hexStringToByteArray(
                                "E0A67598CD1B763BC98C8ABB333E5DDA0CD3AA0E5E1FB5BA8A7B4EABC10BA338FAE06DD4B90FDA70D7CF0CB0C638BE3341BEC0AF8A7330A3307DED2299A0EE606DF035177A239C34A912C202AA5F83B9C4A7CF0235B5316BFC6EFB9A248411258B30B839AF172440F32563056CB67A861158DDD90E6A894C72A5BBEF9E286C6B")),
                computations.getP().getValue());
        assertEquals(
                new BigInteger(
                        1,
                        ArrayConverter.hexStringToByteArray(
                                "D0EC4E50BB290A42E9E355C73D8809345DE2E139")),
                computations.getPrivateKey().getValue());
        assertEquals(
                new BigInteger(
                        1,
                        ArrayConverter.hexStringToByteArray(
                                "E950511EAB424B9A19A2AEB4E159B7844C589C4F")),
                computations.getQ().getValue());
        assertEquals(
                new BigInteger(
                        1,
                        ArrayConverter.hexStringToByteArray(
                                "636155AC9A4633B4665D179F9E4117DF68601F34")),
                computations.getR().getValue());
        assertEquals(
                new BigInteger(
                        1,
                        ArrayConverter.hexStringToByteArray(
                                "6C540B02D9D4852F89DF8CFC99963204F4347704")),
                computations.getS().getValue());
        assertTrue(computations.getSignatureValid());
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray(
                        "302C0214636155AC9A4633B4665D179F9E4117DF68601F3402146C540B02D9D4852F89DF8CFC99963204F4347704"),
                computations.getSignatureBytes().getValue());
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray("616263"),
                computations.getToBeSignedBytes().getValue());
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray("A9993E364706816ABA3E25717850C26C9CD0D89D"),
                computations.getTruncatedHashBytes().getValue());
        assertEquals(
                new BigInteger(
                        1,
                        ArrayConverter.hexStringToByteArray(
                                "5D69A2B1B6988FFA5FA41AFAE8526C15535D7B35")),
                computations.getXr().getValue());
    }

    /** Test of computeEcdsaSignature method, of class SignatureCalculator. */
    @Test
    public void testComputeEcdsaSignature() {
        EcdsaSignatureComputations computations = new EcdsaSignatureComputations();

        BigInteger privateKey =
                new BigInteger(
                        1,
                        ArrayConverter.hexStringToByteArray(
                                "519b423d715f8b581f4fa8ee59f4771a5b44c8130b4e3eacca54a56dda72b464"));
        byte[] toBeSignedBytes =
                ArrayConverter.hexStringToByteArray(
                        "44acf6b7e36c1342c2c5897204fe09504e1e2efb1a900377dbc4e7a6a133ec56");
        computations.setDigestBytes(Modifiable.explicit(toBeSignedBytes));
        computations.setTruncatedHashBytes(
                Modifiable.explicit(
                        toBeSignedBytes)); // The test message is already hashed, so we have to
        // cheat a little
        BigInteger nonce =
                new BigInteger(
                        1,
                        ArrayConverter.hexStringToByteArray(
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
                        ArrayConverter.hexStringToByteArray(
                                "94a1bbb14b906a61a280f245f9e93c7f3b4a6247824f5d33b9670787642a68de")),
                computations.getNonce().getValue());
        assertEquals(
                new BigInteger(
                        1,
                        ArrayConverter.hexStringToByteArray(
                                "519b423d715f8b581f4fa8ee59f4771a5b44c8130b4e3eacca54a56dda72b464")),
                computations.getPrivateKey().getValue());

        assertArrayEquals(
                ArrayConverter.hexStringToByteArray(
                        "44acf6b7e36c1342c2c5897204fe09504e1e2efb1a900377dbc4e7a6a133ec56"),
                computations.getToBeSignedBytes().getValue());
        assertEquals(
                new BigInteger(
                        1,
                        ArrayConverter.hexStringToByteArray(
                                "44acf6b7e36c1342c2c5897204fe09504e1e2efb1a900377dbc4e7a6a133ec56")),
                computations.getTruncatedHash().getValue());
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray(
                        "44acf6b7e36c1342c2c5897204fe09504e1e2efb1a900377dbc4e7a6a133ec56"),
                computations.getTruncatedHashBytes().getValue());
        assertEquals(
                new BigInteger(
                        1,
                        ArrayConverter.hexStringToByteArray(
                                "f3ac8061b514795b8843e3d6629527ed2afd6b1f6a555a7acabb5e6f79c8c2ac")),
                computations.getR().getValue());
        assertEquals(
                new BigInteger(
                        1,
                        ArrayConverter.hexStringToByteArray(
                                "8bf77819ca05a6b2786c76262bf7371cef97b218e96f175a3ccdda2acc058903")),
                computations.getS().getValue());
        assertTrue(computations.getSignatureValid());
    }
}
