/*
 * Protocol-Attacker - A Framework to create Protocol Analysis Tools
 *
 * Copyright 2023-2024 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.protocol.crypto.key;

import de.rub.nds.protocol.constants.FfdhGroupParameters;
import de.rub.nds.protocol.constants.NamedEllipticCurveParameters;
import java.math.BigInteger;
import java.util.Random;
import org.apache.commons.lang3.tuple.Pair;

public class KeyGenerator {

    private static final int MAX_NUMBER_OF_DSA_ITERATIONS = 100;

    private KeyGenerator() {
    }

    public static DhPublicKey generateDhPublicKey(
            BigInteger privateKey, FfdhGroupParameters parameters) {
        return new DhPublicKey(
                privateKey.modPow(parameters.getGenerator(), parameters.getModulus()),
                parameters.getGenerator(),
                parameters.getModulus());
    }

    public static DhPublicKey generateDhPublicKey(
            BigInteger privateKey, BigInteger generator, BigInteger modulus) {
        return new DhPublicKey(privateKey.modPow(generator, modulus), generator, modulus);
    }

    public static DhPublicKey generateDhPublicKey(
            BigInteger privateKey, int bitLength, Random random) {
        BigInteger modulus = BigInteger.probablePrime(bitLength, random); // Not a safe prime...
        BigInteger generator = new BigInteger("2"); // Hardcoded generator
        return new DhPublicKey(privateKey.modPow(generator, modulus), generator, modulus);
    }

    public static EcdhPublicKey generateEcdhPublicKey(
            BigInteger privateKey, NamedEllipticCurveParameters parameters) {
        return new EcdhPublicKey(
                parameters.getGroup().nTimesGroupOperationOnGenerator(privateKey), parameters);
    }

    public static EcdsaPublicKey generateEcdsaPublicKey(
            BigInteger privateKey, NamedEllipticCurveParameters parameters) {
        return new EcdsaPublicKey(
                parameters.getGroup().nTimesGroupOperationOnGenerator(privateKey), parameters);
    }

    public static EddsaPublicKey generateEddsaPublicKey(
            BigInteger privateKey, NamedEllipticCurveParameters parameters) {
        return new EddsaPublicKey(
                parameters.getGroup().nTimesGroupOperationOnGenerator(privateKey), parameters);
    }

    /**
     * @param privateKey A private key that should be used
     * @param pLength 1024-3072 (bits) usually
     * @param qLenght 160-256 (bits)
     * @param random A random number generator
     * @return
     */
    public static DsaPublicKey generateDsaPublicKey(
            BigInteger privateKey, int pLength, int qLenght, Random random) {
        // Prime Number p: A large prime number p is chosen. The length of p (in bits) determines
        // the security level of the DSA system. Common sizes are 1024, 2048, or 3072 bits.
        BigInteger p = BigInteger.probablePrime(pLength, random);
        // Subprime q: Another prime number q is chosen such that q is a divisor of p−1. The length
        // of q is typically 160 or 256 bits. This number qq ensures the security of the discrete
        // logarithm problem in the subgroup of order q.
        BigInteger q;
        int i = 0;
        do {
            q = BigInteger.probablePrime(qLenght, random);
            if (p.subtract(BigInteger.ONE).mod(q).equals(BigInteger.ZERO)) {
                break;
            }
            i++;
            if (i > MAX_NUMBER_OF_DSA_ITERATIONS) {
                throw new IllegalArgumentException("Could not find a suitable q for the given p");
            }
        } while (p.subtract(BigInteger.ONE).mod(q).equals(BigInteger.ZERO));

        BigInteger g;
        BigInteger h;
        i = 0;
        do {
            // h is any number between 2 and p−2 such that g>1. If g=1, a different h is chosen.
            // This should guarantee that h is smaller than p-2 and bigger than 2.
            h = new BigInteger(p.bitLength() - 3, random);
            g = h.modPow(p.subtract(BigInteger.ONE).divide(q), p);
            i++;
            if (i > MAX_NUMBER_OF_DSA_ITERATIONS) {
                throw new IllegalArgumentException(
                        "Could not find a suitable g for the given p and q");
            }
        } while (g == BigInteger.ONE);
        // At this point parameter generation is finished and the public key can be calculated

        return generateDsaPublicKey(privateKey, g, p, q);
    }

    public static DsaPublicKey generateDsaPublicKey(
            BigInteger privateKey, BigInteger g, BigInteger p, BigInteger q) {

        BigInteger y = g.modPow(privateKey, p);

        return new DsaPublicKey(q, y, g, p);
    }

    public static RsaPublicKey generateRsaPublicKey(BigInteger modulus, BigInteger publicExponent) {
        return new RsaPublicKey(modulus, publicExponent);
    }

    public static Pair<RsaPublicKey, RsaPrivateKey> generateRsaKeys(int bitLength, Random random) {
        return generateRsaKeys(new BigInteger("65537"), bitLength, random);
    }

    public static Pair<RsaPublicKey, RsaPrivateKey> generateRsaKeys(
            BigInteger publicExponent, int bitLength, Random random) {
        if (bitLength <= 5) {
            throw new IllegalArgumentException("Bit length must be greater than 5");
        }
        BigInteger modulus;
        BigInteger p;
        BigInteger q;
        do {

            p = BigInteger.probablePrime(bitLength / 2, random);
            if (bitLength % 2 == 0) {
                q = BigInteger.probablePrime(bitLength / 2, random);
            } else {
                q = BigInteger.probablePrime(bitLength / 2 + 1, random);
            }
            modulus = p.multiply(q);
        } while (modulus.bitLength() != bitLength);
        BigInteger phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
        while (phi.gcd(publicExponent).intValue() > 1) {
            publicExponent = BigInteger.probablePrime(bitLength / 2, random);
        }
        BigInteger privateExponent = publicExponent.modInverse(phi);
        return Pair.of(
                new RsaPublicKey(publicExponent, modulus),
                new RsaPrivateKey(privateExponent, modulus));
    }
}
