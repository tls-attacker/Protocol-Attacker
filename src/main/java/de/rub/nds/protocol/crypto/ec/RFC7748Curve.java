/*
 * Protocol-Attacker - A Framework to create Protocol Analysis Tools
 *
 * Copyright 2023-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.protocol.crypto.ec;

import de.rub.nds.modifiablevariable.util.DataConverter;
import java.math.BigInteger;
import java.util.Arrays;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/** Abstract base class for RFC 7748 elliptic curves (X25519 and X448). */
public abstract class RFC7748Curve extends SimulatedMontgomeryCurve {

    private static final Logger LOGGER = LogManager.getLogger();

    protected RFC7748Curve(
            BigInteger a,
            BigInteger b,
            BigInteger modulus,
            BigInteger basePointX,
            BigInteger basePointY,
            BigInteger basePointOrder) {
        super(a, b, modulus, basePointX, basePointY, basePointOrder);
    }

    /**
     * Decodes a scalar value according to RFC 7748 specifications.
     *
     * @param scalar The scalar value to decode
     * @return The decoded scalar value
     */
    public abstract BigInteger decodeScalar(BigInteger scalar);

    /**
     * Decodes an encoded coordinate according to RFC 7748 specifications.
     *
     * @param encCoordinate The encoded coordinate
     * @return The decoded coordinate value
     */
    public abstract BigInteger decodeCoordinate(BigInteger encCoordinate);

    /**
     * Encodes a coordinate according to RFC 7748 specifications.
     *
     * @param coordinate The coordinate to encode
     * @return The encoded coordinate as a byte array
     */
    public abstract byte[] encodeCoordinate(BigInteger coordinate);

    /**
     * Computes the public key from a private key.
     *
     * @param privateKey The private key
     * @return The public key as an encoded byte array
     */
    public byte[] computePublicKey(BigInteger privateKey) {
        privateKey = reduceLongKey(privateKey);
        BigInteger decodedKey = decodeScalar(privateKey);
        Point publicPoint = mult(decodedKey, getBasePoint());

        return encodeCoordinate(publicPoint.getFieldX().getData());
    }

    private byte[] computeSharedSecret(BigInteger privateKey, byte[] publicKey) {
        privateKey = reduceLongKey(privateKey);
        BigInteger decodedCoord = decodeCoordinate(new BigInteger(1, publicKey));
        BigInteger decodedKey = decodeScalar(privateKey);

        Point publicPoint = createAPointOnCurve(decodedCoord);
        Point sharedPoint = mult(decodedKey, publicPoint);
        if (sharedPoint.getFieldX() == null) {
            LOGGER.warn(
                    "Cannot encode point in infinity. Using X coordinate of base point as shared secret");
            return encodeCoordinate(getBasePoint().getFieldX().getData());
        }
        return encodeCoordinate(sharedPoint.getFieldX().getData());
    }

    /**
     * Computes the shared secret from a private key and a decoded public key point.
     *
     * @param privateKey The private key
     * @param publicKey The public key as a decoded point
     * @return The shared secret as an encoded byte array
     */
    public byte[] computeSharedSecretFromDecodedPoint(BigInteger privateKey, Point publicKey) {
        byte[] reEncoded = encodeCoordinate(publicKey.getFieldX().getData());
        return computeSharedSecret(privateKey, reEncoded);
    }

    /**
     * Reduces a key that is longer than the modulus to the appropriate length.
     *
     * @param key The key to reduce
     * @return The reduced key
     */
    public BigInteger reduceLongKey(BigInteger key) {
        byte[] keyBytes = key.toByteArray();
        if (keyBytes.length > DataConverter.bigIntegerToByteArray(getModulus()).length) {
            keyBytes =
                    Arrays.copyOfRange(
                            keyBytes, 0, DataConverter.bigIntegerToByteArray(getModulus()).length);
            return new BigInteger(1, keyBytes);
        } else {
            return key;
        }
    }
}
