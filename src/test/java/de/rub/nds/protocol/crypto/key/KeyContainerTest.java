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
import static org.junit.jupiter.api.Assertions.assertNotNull;

import de.rub.nds.protocol.constants.AsymmetricAlgorithmType;
import de.rub.nds.protocol.constants.FfdhGroupParameters;
import de.rub.nds.protocol.constants.NamedEllipticCurveParameters;
import de.rub.nds.protocol.crypto.ec.Point;
import de.rub.nds.protocol.crypto.ffdh.ExplicitFfdhGroupParameters;
import java.math.BigInteger;
import java.util.Random;
import org.junit.jupiter.api.Test;

public class KeyContainerTest {

    private static final Random RANDOM = new Random(42); // Fixed seed for reproducibility
    private static final BigInteger PRIVATE_KEY = new BigInteger("123456789", 10);
    private static final BigInteger GENERATOR = BigInteger.valueOf(2);
    private static final BigInteger MODULUS = new BigInteger("7919", 10); // Small prime for testing
    private static final NamedEllipticCurveParameters EC_PARAMS =
            NamedEllipticCurveParameters.SECP256R1;

    @Test
    public void testPrivateKeyContainerImplementations() {
        // Test that all PrivateKeyContainer implementations work properly

        // DH Private Key
        FfdhGroupParameters dhParams = new ExplicitFfdhGroupParameters(GENERATOR, MODULUS);
        PrivateKeyContainer dhPrivateKey = new DhPrivateKey(PRIVATE_KEY, dhParams);
        assertNotNull(dhPrivateKey);

        // DSA Private Key
        BigInteger q = new BigInteger("127", 10);
        BigInteger k = new BigInteger("123", 10); // Nonce
        PrivateKeyContainer dsaPrivateKey =
                new DsaPrivateKey(q, PRIVATE_KEY, k, GENERATOR, MODULUS);
        assertNotNull(dsaPrivateKey);

        // ECDH Private Key
        PrivateKeyContainer ecdhPrivateKey = new EcdhPrivateKey(PRIVATE_KEY, EC_PARAMS);
        assertNotNull(ecdhPrivateKey);

        // ECDSA Private Key
        BigInteger nonce = new BigInteger("987654321", 10);
        PrivateKeyContainer ecdsaPrivateKey = new EcdsaPrivateKey(PRIVATE_KEY, nonce, EC_PARAMS);
        assertNotNull(ecdsaPrivateKey);

        // EdDSA Private Key
        PrivateKeyContainer eddsaPrivateKey =
                new EddsaPrivateKey(PRIVATE_KEY, NamedEllipticCurveParameters.CURVE_X25519);
        assertNotNull(eddsaPrivateKey);

        // RSA Private Key
        PrivateKeyContainer rsaPrivateKey = new RsaPrivateKey(PRIVATE_KEY, MODULUS);
        assertNotNull(rsaPrivateKey);
    }

    @Test
    public void testPublicKeyContainerImplementations() {
        // Test that all PublicKeyContainer implementations work properly

        // DH Public Key
        PublicKeyContainer dhPublicKey = new DhPublicKey(PRIVATE_KEY, GENERATOR, MODULUS);
        assertEquals(AsymmetricAlgorithmType.DH, dhPublicKey.getAlgorithmType());
        assertEquals(MODULUS.bitLength(), dhPublicKey.length());

        // DSA Public Key
        BigInteger q = new BigInteger("127", 10);
        BigInteger y = GENERATOR.modPow(PRIVATE_KEY, MODULUS);
        PublicKeyContainer dsaPublicKey = new DsaPublicKey(q, y, GENERATOR, MODULUS);
        assertEquals(AsymmetricAlgorithmType.DSA, dsaPublicKey.getAlgorithmType());
        assertEquals(MODULUS.bitLength(), dsaPublicKey.length());

        // ECDH Public Key
        Point ecPoint = EC_PARAMS.getGroup().nTimesGroupOperationOnGenerator(PRIVATE_KEY);
        PublicKeyContainer ecdhPublicKey = new EcdhPublicKey(ecPoint, EC_PARAMS);
        assertEquals(AsymmetricAlgorithmType.ECDH, ecdhPublicKey.getAlgorithmType());
        assertEquals(EC_PARAMS.getElementSizeBits(), ecdhPublicKey.length());

        // ECDSA Public Key
        PublicKeyContainer ecdsaPublicKey = new EcdsaPublicKey(ecPoint, EC_PARAMS);
        assertEquals(AsymmetricAlgorithmType.ECDSA, ecdsaPublicKey.getAlgorithmType());
        assertEquals(EC_PARAMS.getElementSizeBits(), ecdsaPublicKey.length());

        // EdDSA Public Key
        NamedEllipticCurveParameters edCurve = NamedEllipticCurveParameters.CURVE_X25519;
        Point edPoint = edCurve.getGroup().nTimesGroupOperationOnGenerator(PRIVATE_KEY);
        PublicKeyContainer eddsaPublicKey = new EddsaPublicKey(edPoint, edCurve);
        assertEquals(AsymmetricAlgorithmType.EDDSA, eddsaPublicKey.getAlgorithmType());
        assertEquals(edCurve.getElementSizeBits(), eddsaPublicKey.length());

        // RSA Public Key
        PublicKeyContainer rsaPublicKey = new RsaPublicKey(PRIVATE_KEY, MODULUS);
        assertEquals(AsymmetricAlgorithmType.RSA, rsaPublicKey.getAlgorithmType());
        assertEquals(MODULUS.bitLength(), rsaPublicKey.length());
    }
}
