/*
 * Protocol-Attacker - A framework to create protocol analysis tools
 *
 * Copyright 2023-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.protocol.crypto.signature;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.protocol.constants.HashAlgorithm;
import de.rub.nds.protocol.constants.NamedEllipticCurveParameters;
import de.rub.nds.protocol.crypto.ec.EllipticCurve;
import de.rub.nds.protocol.crypto.ec.Point;
import de.rub.nds.protocol.crypto.hash.HashCalculator;
import de.rub.nds.protocol.exception.CryptoException;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Arrays;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DERSequence;

public class SignatureCalculator {

    private static final Logger LOGGER = LogManager.getLogger();

    public SignatureCalculator() {
    }

    public void computeRsaPkcs1Signature(
            RsaPkcs1SignatureComputations computations,
            BigInteger privateKey,
            BigInteger modulus,
            byte[] toBeSignedBytes,
            HashAlgorithm hashAlgorithm) {
        LOGGER.trace("Computing RSA signature");
        computations.setPrivateKey(privateKey);
        computations.setModulus(modulus);
        computations.setToBeSignedBytes(toBeSignedBytes);
        computations.setHashAlgorithm(hashAlgorithm);
        byte[] digest = HashCalculator.compute(toBeSignedBytes, hashAlgorithm);
        computations.setDigestBytes(digest);
        digest = computations.getDigestBytes().getValue();
        byte[] derEncoded = derEncodePkcs1(hashAlgorithm, digest);
        computations.setDerEncodedDigest(derEncoded);
        derEncoded = computations.getDerEncodedDigest().getValue();
        byte[] padding
                = computePkcs1Padding(
                        derEncoded.length,
                        computations.getModulus().getValue().bitLength()
                        / 8); // TODO not sure this is correct;
        computations.setPadding(padding);
        padding = computations.getPadding().getValue();
        byte[] plainData = ArrayConverter.concatenate(padding, derEncoded);
        computations.setPlainToBeSigned(plainData);
        plainData = computations.getPlainToBeSigned().getValue();
        BigInteger plainInteger = new BigInteger(plainData); // Not sure this is correct
        BigInteger signature
                = plainInteger.modPow(
                        computations.getPrivateKey().getValue(),
                        computations.getModulus().getValue());
        computations.setSignatureBytes(signature.toByteArray()); // Not sure this is correct
    }

    private byte[] computePkcs1Padding(int toBePaddedLength, int modLengthInByte) {
        if (toBePaddedLength + 3 >= modLengthInByte) {
            // Dont pad in this case
            return new byte[0];
        } else {
            try {
                ByteArrayOutputStream stream = new ByteArrayOutputStream();
                stream.write(new byte[]{0, 1});
                while (stream.size()
                        < modLengthInByte - toBePaddedLength - 1) // TODO not sure this is correct
                {
                    stream.write((byte) 0xFF);
                }
                stream.write(0);
                return stream.toByteArray();
            } catch (IOException ex) {
                LOGGER.error("Could not generate padding", ex);
                throw new RuntimeException(ex);
            }
        }
    }

    private byte[] derEncodePkcs1(HashAlgorithm algorithm, byte[] data) {
        ASN1ObjectIdentifier asn1objectIdnetifier = new ASN1ObjectIdentifier("");
        ASN1OctetString asn1octetString
                = ASN1OctetString.getInstance(data); // TODO Not sure this is correct
        ASN1Encodable[] encodables = new ASN1Encodable[]{asn1objectIdnetifier, asn1octetString};
        DERSequence derSequence = new DERSequence(encodables);
        try {
            return derSequence.getEncoded();
        } catch (IOException ex) {
            LOGGER.error("Could not encode der sequence,ex");
            throw new RuntimeException(ex);
        }
    }

    public void computeDsaSignature(
            DsaSignatureComputations computations,
            BigInteger privateKey,
            byte[] toBeSignedBytes,
            BigInteger nonce,
            BigInteger q,
            BigInteger g,
            BigInteger p,
            HashAlgorithm hashAlgorithm) {
        computations.setQ(q);
        computations.setP(p);
        computations.setG(g);
        computations.setNonce(nonce);

        LOGGER.trace("Computing DSA signature");
        int groupSize = q.bitLength() / 8;
        // not persisted in computation as they can be set before the calculation
        LOGGER.debug("g: " + computations.getG().getValue());
        LOGGER.debug("p: " + computations.getP().getValue());
        LOGGER.debug("q: " + computations.getQ().getValue());
        LOGGER.debug("Nonce: " + computations.getNonce().getValue());
        computations.setToBeSignedBytes(toBeSignedBytes);
        byte[] digest = HashCalculator.compute(computations.getToBeSignedBytes().getValue(), hashAlgorithm);
        computations.setDigestBytes(digest);
        digest = computations.getDigestBytes().getValue();

        LOGGER.debug("Digest: " + ArrayConverter.bytesToHexString(digest));

        // z = e[0:l], with l bit length of group order
        byte[] truncatedHashBytes = Arrays.copyOfRange(digest, 0, Math.min(groupSize, digest.length));
        computations.setTruncatedHashBytes(truncatedHashBytes);
        BigInteger truncatedHashNumber = new BigInteger(1, computations.getTruncatedHashBytes().getValue());
        LOGGER.debug("Truncated message digest: " + truncatedHashNumber);

        BigInteger randomKey = computations.getNonce().getValue();
        BigInteger r = computations.getG().getValue().modPow(randomKey, computations.getP().getValue()).mod(computations.getQ().getValue());
        computations.setR(r);
        r = computations.getR().getValue();

        // s = k^-1 * (H(m) + xr)
        BigInteger inverseNonce = randomKey.modInverse(computations.getQ().getValue());

        computations.setInverseNonce(inverseNonce);
        inverseNonce = computations.getInverseNonce().getValue();
        BigInteger xr = computations.getPrivateKey().getValue().multiply(r).mod(computations.getQ().getValue());

        computations.setXr(xr);
        xr = computations.getXr().getValue();
        BigInteger s = inverseNonce.multiply(truncatedHashNumber.add(xr)).mod(computations.getQ().getValue());

        computations.setS(s);
        s = computations.getS().getValue();

        LOGGER.debug("s: " + ArrayConverter.bytesToHexString(s.toByteArray()));
        LOGGER.debug("r: " + ArrayConverter.bytesToHexString(r.toByteArray()));

        ASN1Integer asn1IntegerR = new ASN1Integer(r);
        ASN1Integer asn1IntegerS = new ASN1Integer(inverseNonce);
        ASN1Encodable[] encodables = new ASN1Encodable[]{asn1IntegerR, asn1IntegerS};
        DERSequence derSequence = new DERSequence(encodables);

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        try {
            derSequence.encodeTo(outputStream);
        } catch (IOException ex) {
            throw new CryptoException("Could not write Signature to output stream");
        }
        byte[] completeSignature = outputStream.toByteArray();
        computations.setSignatureBytes(completeSignature);
        computations.setSignatureValid(true);
    }

    public void computeEcdsaSignature(
            EcdsaSignatureComputations computations,
            BigInteger privateKey,
            byte[] toBeSignedBytes,
            BigInteger nonce,
            NamedEllipticCurveParameters ecParameters,
            HashAlgorithm hashAlgorithm) {
        LOGGER.trace("Computing ECDSA signature");
        computations.setEcParameters(ecParameters);
        computations.setHashAlgorithm(hashAlgorithm);
        computations.setNonce(nonce);
        computations.setPrivateKey(privateKey);
        computations.setToBeSignedBytes(toBeSignedBytes);

        EllipticCurve curve = ecParameters.getCurve();
        Point basePoint = curve.getBasePoint();

        BigInteger groupOrder = curve.getBasePointOrder();
        LOGGER.debug("Group order: " + groupOrder);
        int groupSize = groupOrder.bitLength() / 8;
        LOGGER.debug("Group size: " + groupSize);

        // e = Hash(m)
        byte[] hash = HashCalculator.computeMd5(computations.getToBeSignedBytes().getValue());
        computations.setDigestBytes(hash);
        hash = computations.getDigestBytes().getValue();
        LOGGER.debug("Digest: " + ArrayConverter.bytesToHexString(hash));

        // z = e[0:l], with l bit length of group order
        byte[] truncatedHashBytes = Arrays.copyOfRange(hash, 0, Math.min(groupSize, hash.length));
        computations.setTruncatedHashBytes(truncatedHashBytes);
        computations.setTruncatedHash(
                new BigInteger(1, (computations.getTruncatedHashBytes().getValue())));
        BigInteger truncatedHash = computations.getTruncatedHash().getValue();
        LOGGER.debug(
                "Truncated message digest"
                + ArrayConverter.bytesToHexString(truncatedHash.toByteArray()));

        BigInteger inverseNonce;
        BigInteger r;
        BigInteger s;

        // generate values until both s and r aren't 0
        // RM: I dont think we need to do this - the probability of that beein the case by chance
        // should be close to 0
        // and maybe we want this to happen...
        // (x1,y1) = k * G
        Point randomPoint = curve.mult(computations.getNonce().getValue(), basePoint);

        r = randomPoint.getFieldX().getData().mod(groupOrder);
        computations.setrX(r);
        r = computations.getrX().getValue();

        inverseNonce = nonce.modInverse(groupOrder);
        computations.setInverseNonce(inverseNonce);
        inverseNonce = computations.getInverseNonce().getValue();
        s = inverseNonce.multiply(truncatedHash.add(r.multiply(privateKey))).mod(groupOrder);
        computations.setS(s);
        s = computations.getS().getValue();

        LOGGER.debug("R: " + ArrayConverter.bytesToHexString(r.toByteArray()));
        LOGGER.debug("S: " + ArrayConverter.bytesToHexString(s.toByteArray()));

        // ASN.1 encoding of signature as SEQUENCE: {r INTEGER, s INTEGER}
        ASN1Integer asn1IntegerR = new ASN1Integer(r);
        ASN1Integer asn1IntegerS = new ASN1Integer(s);
        ASN1Encodable[] encodables = new ASN1Encodable[]{asn1IntegerR, asn1IntegerS};
        DERSequence derSequence = new DERSequence(encodables);

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        try {
            derSequence.encodeTo(outputStream);
        } catch (IOException ex) {
            throw new CryptoException("Could not write Signature to output stream");
        }
        byte[] completeSignature = outputStream.toByteArray();
        computations.setSignatureBytes(completeSignature);
        computations.setSignatureValid(true);
    }
}
