/*
 * Protocol-Attacker - A Framework to create Protocol Analysis Tools
 *
 * Copyright 2023-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.protocol.crypto.signature;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.protocol.constants.HashAlgorithm;
import de.rub.nds.protocol.constants.SignatureAlgorithm;
import de.rub.nds.protocol.crypto.ec.EllipticCurve;
import de.rub.nds.protocol.crypto.ec.Point;
import de.rub.nds.protocol.crypto.hash.HashCalculator;
import de.rub.nds.protocol.crypto.key.DsaPrivateKey;
import de.rub.nds.protocol.crypto.key.EcdsaPrivateKey;
import de.rub.nds.protocol.crypto.key.EddsaPrivateKey;
import de.rub.nds.protocol.crypto.key.PrivateKeyContainer;
import de.rub.nds.protocol.crypto.key.RsaPrivateKey;
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
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;

public class SignatureCalculator {

    private static final Logger LOGGER = LogManager.getLogger();

    public SignatureCalculator() {}

    public void computeSignature(
            SignatureComputations computations,
            PrivateKeyContainer privateKey,
            byte[] toBeSignedBytes,
            SignatureAlgorithm signatureAlgorithm,
            HashAlgorithm hashAlgorithm) {
        if (computations instanceof RsaSsaPssSignatureComputations) {
            // Check That parameters are compatible
            if (!(privateKey instanceof RsaPrivateKey)) {
                throw new IllegalArgumentException(
                        "RSA SignatureComputations must be used with a RSA PrivateKey");
            }
            if (((RsaSsaPssSignatureComputations) computations).getSalt() == null) {
                throw new IllegalArgumentException(
                        "PSS must be used with a salt already prepared in the computations class");
            }
            computeRsaPssSignature(
                    (RsaSsaPssSignatureComputations) computations,
                    (RsaPrivateKey) privateKey,
                    toBeSignedBytes,
                    hashAlgorithm,
                    ((RsaSsaPssSignatureComputations) computations).getSalt().getValue(),
                    HashAlgorithm.SHA1);
        } else if (computations instanceof RsaPkcs1SignatureComputations) {
            // Check That parameters are compatible
            if (!(privateKey instanceof RsaPrivateKey)) {
                throw new IllegalArgumentException(
                        "RSA SignatureComputations must be used with a RSA PrivateKey");
            }
            computeRsaPkcs1Signature(
                    (RsaPkcs1SignatureComputations) computations,
                    (RsaPrivateKey) privateKey,
                    toBeSignedBytes,
                    hashAlgorithm);
        } else if (computations instanceof DsaSignatureComputations) {
            // Check That parameters are compatible
            if (!(privateKey instanceof DsaPrivateKey)) {
                throw new IllegalArgumentException(
                        "DSA SignatureComputations must be used with a DSA PrivateKey");
            }
            computeDsaSignature(
                    (DsaSignatureComputations) computations,
                    (DsaPrivateKey) privateKey,
                    toBeSignedBytes,
                    hashAlgorithm);
        } else if (computations instanceof EcdsaSignatureComputations) {
            // Check That parameters are compatible
            if (!(privateKey instanceof EcdsaPrivateKey)) {
                throw new IllegalArgumentException(
                        "ECDSA SignatureComputations must be used with a ECDSA PrivateKey");
            }
            computeEcdsaSignature(
                    (EcdsaSignatureComputations) computations,
                    (EcdsaPrivateKey) privateKey,
                    toBeSignedBytes,
                    hashAlgorithm);
        } else if (computations instanceof EddsaSignatureComputations) {
            // Check That parameters are compatible
            if (!(privateKey instanceof EddsaPrivateKey)) {
                throw new IllegalArgumentException(
                        "EdDSA SignatureComputations must be used with a EdDSA PrivateKey");
            }
            computeEddsaSignature(
                    (EddsaSignatureComputations) computations,
                    (EddsaPrivateKey) privateKey,
                    toBeSignedBytes,
                    hashAlgorithm);
        } else if (computations instanceof GostSignatureComputations) {
            throw new UnsupportedOperationException("Unsupported operation");
        } else if (computations instanceof NoSignatureComputations) {
            // Nothing to do
        } else {
            throw new UnsupportedOperationException("Unsupported operation");
        }
    }

    public void computeEddsaSignature(
            EddsaSignatureComputations computations,
            EddsaPrivateKey privateKey,
            byte[] toBeSignedBytes,
            HashAlgorithm hashAlgorithm) {
        throw new UnsupportedOperationException("Unsupported operation");
    }

    public void computeRsaPssSignature(
            RsaSsaPssSignatureComputations computations,
            RsaPrivateKey privateKey,
            byte[] toBeSignedBytes,
            HashAlgorithm hashAlgorithm,
            byte[] salt,
            HashAlgorithm mgf1Algorithm) {
        LOGGER.trace("Computing RSA-PSS signature");

        computations.setPrivateKey(privateKey.getPrivateExponent());
        computations.setModulus(privateKey.getModulus());
        computations.setToBeSignedBytes(toBeSignedBytes);
        computations.setHashAlgorithm(hashAlgorithm);
        computations.setSalt(salt);

        // Hash the message
        byte[] digest =
                HashCalculator.compute(computations.getToBeSignedBytes().getValue(), hashAlgorithm);
        computations.setDigestBytes(digest);
        digest = computations.getDigestBytes().getValue();
        LOGGER.debug("Digest: {}", digest);

        // M' = (0x)00 00 00 00 00 00 00 00 || mHash || salt
        byte[] paddedSaltedDigest =
                ArrayConverter.concatenate(new byte[8], digest, computations.getSalt().getValue());
        computations.setPaddedSaltedDigest(paddedSaltedDigest);
        paddedSaltedDigest = computations.getPaddedSaltedDigest().getValue();
        LOGGER.debug("Padded salted digest: {}", paddedSaltedDigest);

        // Hash M' to get H
        byte[] hValue = HashCalculator.compute(paddedSaltedDigest, hashAlgorithm);
        computations.setHValue(hValue);
        hValue = computations.getHValue().getValue();
        LOGGER.debug("H: {}", hValue);

        // Generate padding string PS, which is a string of zero bytes
        int emBits = computations.getModulus().getValue().bitLength() - 1;
        int emLength = (emBits + 7) / 8;
        int psLenght = emLength - computations.getSalt().getValue().length - hValue.length - 2;
        if (psLenght < 0) {
            LOGGER.warn("PS length is negative. Overwritting with 0");
            psLenght = 0;
        }
        byte[] psValue = new byte[psLenght];
        computations.setPsValue(psValue);
        psValue = computations.getPsValue().getValue();
        LOGGER.debug("Ps value: {}", psValue);
        // Generate the DB = PS || 0x01 || salt
        byte[] db =
                ArrayConverter.concatenate(
                        psValue, new byte[] {0x01}, computations.getSalt().getValue());
        computations.setDbValue(db);
        db = computations.getDbValue().getValue();
        LOGGER.debug("DB: {}", db);
        // Mask generation function (MGF1)
        byte[] dbMask = maskGeneratorFunction1(hValue, mgf1Algorithm, emLength - hValue.length - 1);
        LOGGER.debug("DB mask: {}", dbMask);
        byte[] maskedDB = mask(db, dbMask);
        computations.setMaskedDb(maskedDB);
        maskedDB = computations.getMaskedDb().getValue();
        LOGGER.debug("Masked DB: {}", maskedDB);
        computations.setTfValue(new byte[] {(byte) 0xBC});

        int firstByteMask = 0xff >>> ((emLength * 8) - emBits);
        if (maskedDB.length > 0) {
            maskedDB[0] &= firstByteMask;
        }
        // Construct the encoded message EM = maskedDB || H || 0xBC
        byte[] em =
                ArrayConverter.concatenate(maskedDB, hValue, computations.getTfValue().getValue());
        computations.setEmValue(em);
        em = computations.getEmValue().getValue();
        LOGGER.debug("EM: {}", em);
        // Convert EM to an integer
        BigInteger emInteger = new BigInteger(1, em);

        // Signature calculation: s = (emInteger^d) mod n
        BigInteger signature =
                emInteger.modPow(
                        computations.getPrivateKey().getValue(),
                        computations.getModulus().getValue());
        computations.setSignatureBytes(ArrayConverter.bigIntegerToByteArray(signature));
        computations.setSignatureValid(true);
    }

    private byte[] mask(byte[] value, byte[] mask) {
        // Usually value and mask will be of equal length, but invalid values may cause this to not
        // hold
        // that is why we take the minimum of both lengths here.
        int length = Math.min(value.length, mask.length);
        byte[] maskedValue = new byte[value.length];
        for (int i = 0; i < length; i++) {
            maskedValue[i] = (byte) (value[i] ^ mask[i]);
        }
        return maskedValue;
    }

    private byte[] maskGeneratorFunction1(byte[] input, HashAlgorithm mgfAlgorithm, int length) {
        int mgfhLen = mgfAlgorithm.getBitLength() / 8;
        byte[] mask = new byte[length];
        byte[] hashBuf = new byte[mgfhLen];
        byte[] counterBytes = new byte[4];
        int counter = 0;

        while (counter < (length / mgfhLen)) {
            counterBytes = ArrayConverter.intToBytes(counter, 4);

            hashBuf =
                    HashCalculator.compute(
                            ArrayConverter.concatenate(input, counterBytes), mgfAlgorithm);
            System.arraycopy(hashBuf, 0, mask, counter * mgfhLen, mgfhLen);

            counter++;
        }

        if ((counter * mgfhLen) < length) {
            counterBytes = ArrayConverter.intToBytes(counter, 4);

            hashBuf =
                    HashCalculator.compute(
                            ArrayConverter.concatenate(input, counterBytes), mgfAlgorithm);

            System.arraycopy(
                    hashBuf, 0, mask, counter * mgfhLen, mask.length - (counter * mgfhLen));
        }

        return mask;
    }

    public void computeRsaPkcs1Signature(
            RsaPkcs1SignatureComputations computations,
            RsaPrivateKey privateKey,
            byte[] toBeSignedBytes,
            HashAlgorithm hashAlgorithm) {
        LOGGER.trace("Computing RSA signature");
        computations.setPrivateKey(privateKey.getPrivateExponent());
        computations.setModulus(privateKey.getModulus());
        computations.setToBeSignedBytes(toBeSignedBytes);
        computations.setHashAlgorithm(hashAlgorithm);
        byte[] derEncoded;
        if (hashAlgorithm != HashAlgorithm.NONE) {
            byte[] digest = HashCalculator.compute(toBeSignedBytes, hashAlgorithm);
            computations.setDigestBytes(digest);
            digest = computations.getDigestBytes().getValue();
            derEncoded = derEncodePkcs1(hashAlgorithm, digest);
            computations.setDerEncodedDigest(derEncoded);
            derEncoded = computations.getDerEncodedDigest().getValue();
        } else {
            computations.setDigestBytes(computations.getToBeSignedBytes().getValue());
            computations.setDerEncodedDigest(computations.getDigestBytes().getValue());
            derEncoded = computations.getDerEncodedDigest().getValue();
        }
        byte[] padding =
                computePkcs1Padding(
                        derEncoded.length,
                        ArrayConverter.bigIntegerToByteArray(computations.getModulus().getValue())
                                .length);
        computations.setPadding(padding);
        padding = computations.getPadding().getValue();
        byte[] plainData = ArrayConverter.concatenate(padding, derEncoded);
        computations.setPlainToBeSigned(plainData);
        plainData = computations.getPlainToBeSigned().getValue();
        BigInteger plainInteger = new BigInteger(plainData);
        BigInteger signature =
                plainInteger.modPow(
                        computations.getPrivateKey().getValue(),
                        computations.getModulus().getValue());
        computations.setSignatureBytes(ArrayConverter.bigIntegerToByteArray(signature));
        computations.setSignatureValid(true);
    }

    private byte[] computePkcs1Padding(int toBePaddedLength, int modLengthInByte) {
        if (toBePaddedLength + 3 >= modLengthInByte) {
            // Dont pad in this case
            return new byte[0];
        } else {
            try {
                ByteArrayOutputStream stream = new ByteArrayOutputStream();
                stream.write(new byte[] {0, 1});
                while (stream.size() < modLengthInByte - toBePaddedLength - 1) {
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
        ASN1ObjectIdentifier asn1objectIdnetifier =
                new ASN1ObjectIdentifier(algorithm.getHashAlgorithmIdentifierOid());
        ASN1OctetString asn1octetString = new DEROctetString(data);
        ASN1Encodable[] encodables = new ASN1Encodable[] {asn1objectIdnetifier, DERNull.INSTANCE};
        DERSequence derSequence = new DERSequence(encodables);
        ASN1Encodable[] encodables2 = new ASN1Encodable[] {derSequence, asn1octetString};
        DERSequence derSequence2 = new DERSequence(encodables2);

        try {
            return derSequence2.getEncoded();
        } catch (IOException ex) {
            LOGGER.error("Could not encode der sequence", ex);
            throw new RuntimeException(ex);
        }
    }

    public void computeDsaSignature(
            DsaSignatureComputations computations,
            DsaPrivateKey privateKey,
            byte[] toBeSignedBytes,
            HashAlgorithm hashAlgorithm) {
        computations.setQ(privateKey.getQ());
        computations.setP(privateKey.getModulus());
        computations.setG(privateKey.getGenerator());
        computations.setNonce(privateKey.getK());
        computations.setPrivateKey(privateKey.getX());

        LOGGER.trace("Computing DSA signature");
        int groupSize = ArrayConverter.bigIntegerToByteArray(privateKey.getQ()).length;
        // not persisted in computation as they can be set before the calculation
        LOGGER.debug("g: " + computations.getG().getValue());
        LOGGER.debug("p: " + computations.getP().getValue());
        LOGGER.debug("q: " + computations.getQ().getValue());
        LOGGER.debug("Nonce: " + computations.getNonce().getValue());
        computations.setToBeSignedBytes(toBeSignedBytes);
        byte[] digest =
                HashCalculator.compute(computations.getToBeSignedBytes().getValue(), hashAlgorithm);
        computations.setDigestBytes(digest);
        digest = computations.getDigestBytes().getValue();
        LOGGER.debug(
                "toBeSignedBytes: "
                        + ArrayConverter.bytesToHexString(
                                computations.getToBeSignedBytes().getValue()));

        LOGGER.debug(
                "Digest: "
                        + ArrayConverter.bytesToHexString(
                                computations.getDigestBytes().getValue()));

        // z = e[0:l], with l bit length of group order
        byte[] truncatedHashBytes =
                Arrays.copyOfRange(digest, 0, Math.min(groupSize, digest.length));
        computations.setTruncatedHashBytes(truncatedHashBytes);
        BigInteger truncatedHashNumber =
                new BigInteger(1, computations.getTruncatedHashBytes().getValue());
        LOGGER.debug("Truncated message digest: " + truncatedHashNumber);

        BigInteger randomKey = computations.getNonce().getValue();
        BigInteger r =
                computations
                        .getG()
                        .getValue()
                        .modPow(randomKey, computations.getP().getValue())
                        .mod(computations.getQ().getValue());
        computations.setR(r);
        r = computations.getR().getValue();

        // s = k^-1 * (H(m) + xr)
        BigInteger inverseNonce = randomKey.modInverse(computations.getQ().getValue());

        computations.setInverseNonce(inverseNonce);
        inverseNonce = computations.getInverseNonce().getValue();
        BigInteger xr =
                computations
                        .getPrivateKey()
                        .getValue()
                        .multiply(r)
                        .mod(computations.getQ().getValue());

        computations.setXr(xr);
        xr = computations.getXr().getValue();
        LOGGER.debug("Xr: " + xr);

        BigInteger s =
                inverseNonce
                        .multiply(truncatedHashNumber.add(xr))
                        .mod(computations.getQ().getValue());

        computations.setS(s);
        s = computations.getS().getValue();

        LOGGER.debug("s: " + ArrayConverter.bytesToHexString(s.toByteArray()));
        LOGGER.debug("r: " + ArrayConverter.bytesToHexString(r.toByteArray()));

        ASN1Integer asn1IntegerR = new ASN1Integer(r);
        ASN1Integer asn1IntegerS = new ASN1Integer(s);
        ASN1Encodable[] encodables = new ASN1Encodable[] {asn1IntegerR, asn1IntegerS};
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

    public void computeRawEcdsaSignature(
            EcdsaSignatureComputations computations,
            EcdsaPrivateKey privateKey,
            byte[] toBeSignedBytes,
            HashAlgorithm hashAlgorithm) {
        LOGGER.trace("Computing ECDSA signature");
        computations.setEcParameters(privateKey.getParameters());
        computations.setHashAlgorithm(hashAlgorithm);
        computations.setNonce(privateKey.getNonce());
        computations.setPrivateKey(privateKey.getPrivateKey());
        computations.setToBeSignedBytes(toBeSignedBytes);

        EllipticCurve curve = computations.getEcParameters().getGroup();
        Point basePoint = curve.getBasePoint();

        BigInteger groupOrder = curve.getBasePointOrder();
        LOGGER.debug("Group order: " + groupOrder);
        int groupSize = groupOrder.bitLength() / 8;
        LOGGER.debug("Group size: " + groupSize);

        // e = Hash(m)
        byte[] hash =
                HashCalculator.compute(computations.getToBeSignedBytes().getValue(), hashAlgorithm);
        computations.setDigestBytes(hash);
        hash = computations.getDigestBytes().getValue();
        LOGGER.debug("Digest: " + ArrayConverter.bytesToHexString(hash));

        // z = e[0:l], with l bit length of group order
        byte[] truncatedHashBytes = Arrays.copyOfRange(hash, 0, Math.min(groupSize, hash.length));
        computations.setTruncatedHashBytes(truncatedHashBytes);

        LOGGER.debug(
                "TruncatedHashBytes: "
                        + ArrayConverter.bytesToHexString(
                                computations.getTruncatedHashBytes().getValue()));
        computations.setTruncatedHash(
                new BigInteger(1, (computations.getTruncatedHashBytes().getValue())));
        BigInteger truncatedHash = computations.getTruncatedHash().getValue();
        LOGGER.debug("Truncated hash: {}", truncatedHash);
        BigInteger inverseNonce;
        BigInteger r;
        BigInteger s;

        Point randomPoint = curve.mult(computations.getNonce().getValue(), basePoint);

        r = randomPoint.getFieldX().getData().mod(curve.getBasePointOrder());
        computations.setR(r);
        r = computations.getR().getValue();

        LOGGER.debug("R: " + r);
        inverseNonce =
                computations.getPrivateKey().getValue().modInverse(curve.getBasePointOrder());

        computations.setInverseNonce(inverseNonce);
        inverseNonce = computations.getInverseNonce().getValue();
        LOGGER.debug("Inverse Nonce: {}", inverseNonce);
        LOGGER.debug(
                "Verify: {}",
                (inverseNonce.multiply(computations.getNonce().getValue()))
                        .mod(curve.getBasePointOrder()));
        BigInteger rd = r.multiply(privateKey.getPrivateKey());
        rd = rd.mod(curve.getBasePointOrder());
        BigInteger multiplier = (rd.add(truncatedHash));
        multiplier = multiplier.mod(curve.getBasePointOrder());
        s = inverseNonce.multiply(multiplier);
        s = s.mod(curve.getBasePointOrder());

        computations.setS(s);
        s = computations.getS().getValue();

        LOGGER.debug("S: {}", s);
        LOGGER.debug("CurveBasePointOrder: {}", curve.getBasePointOrder().toByteArray());
        LOGGER.debug("Modulus: {}", curve.getModulus().toByteArray());

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        try {
            outputStream.write(ArrayConverter.bigIntegerToByteArray(r, 32, true));
            outputStream.write(ArrayConverter.bigIntegerToByteArray(s, 32, true));
        } catch (IOException ex) {
            throw new CryptoException("Could not write Signature to output stream");
        }
        byte[] completeSignature = outputStream.toByteArray();
        computations.setSignatureBytes(completeSignature);
        computations.setSignatureValid(true);
    }

    public void computeEcdsaSignature(
            EcdsaSignatureComputations computations,
            EcdsaPrivateKey privateKey,
            byte[] toBeSignedBytes,
            HashAlgorithm hashAlgorithm) {
        LOGGER.trace("Computing ECDSA signature");
        computations.setEcParameters(privateKey.getParameters());
        computations.setHashAlgorithm(hashAlgorithm);
        computations.setNonce(privateKey.getNonce());
        computations.setPrivateKey(privateKey.getPrivateKey());
        computations.setToBeSignedBytes(toBeSignedBytes);

        EllipticCurve curve = computations.getEcParameters().getGroup();
        Point basePoint = curve.getBasePoint();

        BigInteger groupOrder = curve.getBasePointOrder();
        LOGGER.debug("Group order: " + groupOrder);
        int groupSize = groupOrder.bitLength() / 8;
        LOGGER.debug("Group size: " + groupSize);

        // e = Hash(m)
        byte[] hash =
                HashCalculator.compute(computations.getToBeSignedBytes().getValue(), hashAlgorithm);
        computations.setDigestBytes(hash);
        hash = computations.getDigestBytes().getValue();
        LOGGER.debug("Digest: " + ArrayConverter.bytesToHexString(hash));

        // z = e[0:l], with l bit length of group order
        byte[] truncatedHashBytes = Arrays.copyOfRange(hash, 0, Math.min(groupSize, hash.length));
        computations.setTruncatedHashBytes(truncatedHashBytes);

        LOGGER.debug(
                "TruncatedHashBytes: "
                        + ArrayConverter.bytesToHexString(
                                computations.getTruncatedHashBytes().getValue()));
        computations.setTruncatedHash(
                new BigInteger(1, (computations.getTruncatedHashBytes().getValue())));
        BigInteger truncatedHash = computations.getTruncatedHash().getValue();
        LOGGER.debug("Truncated hash: {}", truncatedHash);
        BigInteger inverseNonce;
        BigInteger r;
        BigInteger s;

        Point randomPoint = curve.mult(computations.getNonce().getValue(), basePoint);

        r = randomPoint.getFieldX().getData().mod(curve.getBasePointOrder());
        computations.setR(r);
        r = computations.getR().getValue();

        LOGGER.debug("R: {}", r);
        inverseNonce = computations.getNonce().getValue().modInverse(curve.getBasePointOrder());

        computations.setInverseNonce(inverseNonce);
        inverseNonce = computations.getInverseNonce().getValue();
        LOGGER.debug("Inverse Nonce: {}", inverseNonce);
        LOGGER.debug(
                "Verify: {}",
                inverseNonce
                        .multiply(computations.getNonce().getValue())
                        .mod(curve.getBasePointOrder()));
        BigInteger rd = r.multiply(privateKey.getPrivateKey());
        rd = rd.mod(curve.getBasePointOrder());
        BigInteger multiplier = (rd.add(truncatedHash));
        multiplier = multiplier.mod(curve.getBasePointOrder());
        s = inverseNonce.multiply(multiplier);
        s = s.mod(curve.getBasePointOrder());

        computations.setS(s);
        s = computations.getS().getValue();

        LOGGER.debug("S: {}", s);
        LOGGER.debug("CurveBasePointOrder: {}", curve.getBasePointOrder().toByteArray());
        LOGGER.debug("Modulus: {}", curve.getModulus().toByteArray());

        // ASN.1 encoding of signature as SEQUENCE: {r INTEGER, s INTEGER}
        ASN1Integer asn1IntegerR = new ASN1Integer(r);
        ASN1Integer asn1IntegerS = new ASN1Integer(s);
        ASN1Encodable[] encodables = new ASN1Encodable[] {asn1IntegerR, asn1IntegerS};
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

    public SignatureComputations createSignatureComputations(
            SignatureAlgorithm signatureAlgorithm) {
        if (signatureAlgorithm == null) {
            return new NoSignatureComputations();
        }
        switch (signatureAlgorithm) {
            case DSA:
                return new DsaSignatureComputations();
            case ECDSA:
                return new EcdsaSignatureComputations();
            case ED25519:
            case ED448:
                return new EddsaSignatureComputations();
            case GOSTR34102001:
            case GOSTR34102012_256:
            case GOSTR34102012_512:
                return new GostSignatureComputations();
            case RSA_PKCS1:
                return new RsaPkcs1SignatureComputations();
            case RSA_SSA_PSS:
                return new RsaSsaPssSignatureComputations();
            default:
                throw new UnsupportedOperationException(
                        "Unsupported signature algorithm: " + signatureAlgorithm);
        }
    }
}
