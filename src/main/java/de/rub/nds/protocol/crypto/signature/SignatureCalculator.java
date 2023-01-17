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
import static java.lang.Math.random;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.logging.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1OutputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERSequence;

public class SignatureCalculator {

    private static final Logger LOGGER = LogManager.getLogger();

    public SignatureCalculator() {
    }

    public void computeEcdsaSignature(EcdsaSignatureComputations computations, BigInteger privateKey, byte[] toBeSignedBytes, BigInteger nonce, NamedEllipticCurveParameters ecParameters, HashAlgorithm hashAlgorithm) {
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
        computations.setTruncatedHash(new BigInteger(1, (computations.getTruncatedHashBytes().getValue())));
        BigInteger truncatedHash = computations.getTruncatedHash().getValue();
        LOGGER.debug("Truncated message digest" + ArrayConverter.bytesToHexString(truncatedHash.toByteArray()));

        BigInteger inverseNonce;
        BigInteger r;
        BigInteger s;

        // generate values until both s and r aren't 0
        //RM: I dont think we need to do this - the probability of that beein the case by chance should be close to 0
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
