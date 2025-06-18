/*
 * Protocol-Attacker - A Framework to create Protocol Analysis Tools
 *
 * Copyright 2023-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.protocol.crypto.signature;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.biginteger.ModifiableBigInteger;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.protocol.constants.HashAlgorithm;
import de.rub.nds.protocol.constants.NamedEllipticCurveParameters;
import java.math.BigInteger;

/**
 * Computation container for ECDSA (Elliptic Curve Digital Signature Algorithm) signatures.
 * Stores elliptic curve parameters, private key d, nonce k, and signature components r and s.
 */
public class EcdsaSignatureComputations extends SignatureComputations {

    private NamedEllipticCurveParameters ecParameters;

    private HashAlgorithm hashAlgorithm;

    private ModifiableBigInteger privateKey; // d

    private ModifiableBigInteger nonce; // k

    private ModifiableBigInteger inverseNonce; // k^-1

    private ModifiableBigInteger s; // s
    private ModifiableBigInteger r; // r

    private ModifiableByteArray truncatedHashBytes;

    private ModifiableBigInteger truncatedHash;

    /** Constructs a new EcdsaSignatureComputations instance. */
    public EcdsaSignatureComputations() {}

    /**
     * Gets the truncated hash bytes used in ECDSA computation.
     *
     * @return the truncated hash bytes
     */
    public ModifiableByteArray getTruncatedHashBytes() {
        return truncatedHashBytes;
    }

    /**
     * Sets the truncated hash bytes used in ECDSA computation.
     *
     * @param truncatedHashBytes the truncated hash bytes to set
     */
    public void setTruncatedHashBytes(ModifiableByteArray truncatedHashBytes) {
        this.truncatedHashBytes = truncatedHashBytes;
    }

    /**
     * Sets the truncated hash bytes used in ECDSA computation.
     *
     * @param truncatedHashBytes the truncated hash bytes to set as byte array
     */
    public void setTruncatedHashBytes(byte[] truncatedHashBytes) {
        this.truncatedHashBytes =
                ModifiableVariableFactory.safelySetValue(
                        this.truncatedHashBytes, truncatedHashBytes);
    }

    /**
     * Gets the truncated hash value as BigInteger.
     *
     * @return the truncated hash value
     */
    public ModifiableBigInteger getTruncatedHash() {
        return truncatedHash;
    }

    /**
     * Sets the truncated hash value.
     *
     * @param truncatedHash the truncated hash value to set
     */
    public void setTruncatedHash(ModifiableBigInteger truncatedHash) {
        this.truncatedHash = truncatedHash;
    }

    /**
     * Sets the truncated hash value.
     *
     * @param truncatedHash the truncated hash value to set as BigInteger
     */
    public void setTruncatedHash(BigInteger truncatedHash) {
        this.truncatedHash =
                ModifiableVariableFactory.safelySetValue(this.truncatedHash, truncatedHash);
    }

    /**
     * Gets the elliptic curve parameters used for ECDSA.
     *
     * @return the elliptic curve parameters
     */
    public NamedEllipticCurveParameters getEcParameters() {
        return ecParameters;
    }

    /**
     * Sets the elliptic curve parameters used for ECDSA.
     *
     * @param ecParameters the elliptic curve parameters to set
     */
    public void setEcParameters(NamedEllipticCurveParameters ecParameters) {
        this.ecParameters = ecParameters;
    }

    /**
     * Gets the hash algorithm used for ECDSA signature computation.
     *
     * @return the hash algorithm
     */
    public HashAlgorithm getHashAlgorithm() {
        return hashAlgorithm;
    }

    /**
     * Sets the hash algorithm used for ECDSA signature computation.
     *
     * @param hashAlgorithm the hash algorithm to set
     */
    public void setHashAlgorithm(HashAlgorithm hashAlgorithm) {
        this.hashAlgorithm = hashAlgorithm;
    }

    /**
     * Gets the private key (d) used for ECDSA signature generation.
     *
     * @return the private key
     */
    public ModifiableBigInteger getPrivateKey() {
        return privateKey;
    }

    /**
     * Sets the private key (d) used for ECDSA signature generation.
     *
     * @param privateKey the private key to set as BigInteger
     */
    public void setPrivateKey(BigInteger privateKey) {
        this.privateKey = ModifiableVariableFactory.safelySetValue(this.privateKey, privateKey);
    }

    /**
     * Sets the private key (d) used for ECDSA signature generation.
     *
     * @param privateKey the private key to set
     */
    public void setPrivateKey(ModifiableBigInteger privateKey) {
        this.privateKey = privateKey;
    }

    /**
     * Gets the nonce (k) used in ECDSA signature generation.
     *
     * @return the nonce value
     */
    public ModifiableBigInteger getNonce() {
        return nonce;
    }

    /**
     * Sets the nonce (k) used in ECDSA signature generation.
     *
     * @param nonce the nonce value to set as BigInteger
     */
    public void setNonce(BigInteger nonce) {
        this.nonce = ModifiableVariableFactory.safelySetValue(this.nonce, nonce);
    }

    /**
     * Sets the nonce (k) used in ECDSA signature generation.
     *
     * @param nonce the nonce value to set
     */
    public void setNonce(ModifiableBigInteger nonce) {
        this.nonce = nonce;
    }

    /**
     * Gets the inverse nonce (k^-1) used in ECDSA signature generation.
     *
     * @return the inverse nonce value
     */
    public ModifiableBigInteger getInverseNonce() {
        return inverseNonce;
    }

    /**
     * Sets the inverse nonce (k^-1) used in ECDSA signature generation.
     *
     * @param inverseNonce the inverse nonce value to set as BigInteger
     */
    public void setInverseNonce(BigInteger inverseNonce) {
        this.inverseNonce =
                ModifiableVariableFactory.safelySetValue(this.inverseNonce, inverseNonce);
    }

    /**
     * Sets the inverse nonce (k^-1) used in ECDSA signature generation.
     *
     * @param inverseNonce the inverse nonce value to set
     */
    public void setInverseNonce(ModifiableBigInteger inverseNonce) {
        this.inverseNonce = inverseNonce;
    }

    /**
     * Gets the s component of the ECDSA signature.
     *
     * @return the s component
     */
    public ModifiableBigInteger getS() {
        return s;
    }

    /**
     * Sets the s component of the ECDSA signature.
     *
     * @param s the s component to set as BigInteger
     */
    public void setS(BigInteger s) {
        this.s = ModifiableVariableFactory.safelySetValue(this.s, s);
    }

    /**
     * Sets the s component of the ECDSA signature.
     *
     * @param s the s component to set
     */
    public void setS(ModifiableBigInteger s) {
        this.s = s;
    }

    /**
     * Gets the r component of the ECDSA signature.
     *
     * @return the r component
     */
    public ModifiableBigInteger getR() {
        return r;
    }

    /**
     * Sets the r component of the ECDSA signature.
     *
     * @param r the r component to set as BigInteger
     */
    public void setR(BigInteger r) {
        this.r = ModifiableVariableFactory.safelySetValue(this.r, r);
    }

    /**
     * Sets the r component of the ECDSA signature.
     *
     * @param r the r component to set
     */
    public void setR(ModifiableBigInteger r) {
        this.r = r;
    }
}
