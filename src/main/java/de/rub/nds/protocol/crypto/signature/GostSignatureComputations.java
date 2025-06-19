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
 * Computations for GOST signature algorithms. Note: GOST implementation is currently low priority
 * and may be incomplete.
 */
public class GostSignatureComputations extends SignatureComputations {

    private NamedEllipticCurveParameters ecParameters;

    private HashAlgorithm hashAlgorithm;

    private ModifiableBigInteger privateKey; // d

    private ModifiableBigInteger nonce; // k

    private ModifiableBigInteger inverseNonce; // k^-1

    private ModifiableBigInteger rX; // x coordinate of k*G

    private ModifiableBigInteger s; // s

    private ModifiableByteArray truncatedHashBytes;

    private ModifiableBigInteger truncatedHash;

    /** Constructs a new GostSignatureComputations instance. */
    public GostSignatureComputations() {}

    /**
     * Gets the truncated hash bytes used in GOST computation.
     *
     * @return the truncated hash bytes
     */
    public ModifiableByteArray getTruncatedHashBytes() {
        return truncatedHashBytes;
    }

    /**
     * Sets the truncated hash bytes used in GOST computation.
     *
     * @param truncatedHashBytes the truncated hash bytes to set
     */
    public void setTruncatedHashBytes(ModifiableByteArray truncatedHashBytes) {
        this.truncatedHashBytes = truncatedHashBytes;
    }

    /**
     * Sets the truncated hash bytes used in GOST computation.
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
     * Gets the elliptic curve parameters used for GOST.
     *
     * @return the elliptic curve parameters
     */
    public NamedEllipticCurveParameters getEcParameters() {
        return ecParameters;
    }

    /**
     * Sets the elliptic curve parameters used for GOST.
     *
     * @param ecParameters the elliptic curve parameters to set
     */
    public void setEcParameters(NamedEllipticCurveParameters ecParameters) {
        this.ecParameters = ecParameters;
    }

    /**
     * Gets the hash algorithm used for GOST signature computation.
     *
     * @return the hash algorithm
     */
    public HashAlgorithm getHashAlgorithm() {
        return hashAlgorithm;
    }

    /**
     * Sets the hash algorithm used for GOST signature computation.
     *
     * @param hashAlgorithm the hash algorithm to set
     */
    public void setHashAlgorithm(HashAlgorithm hashAlgorithm) {
        this.hashAlgorithm = hashAlgorithm;
    }

    /**
     * Gets the private key (d) used for GOST signature generation.
     *
     * @return the private key
     */
    public ModifiableBigInteger getPrivateKey() {
        return privateKey;
    }

    /**
     * Sets the private key (d) used for GOST signature generation.
     *
     * @param privateKey the private key to set as BigInteger
     */
    public void setPrivateKey(BigInteger privateKey) {
        this.privateKey = ModifiableVariableFactory.safelySetValue(this.privateKey, privateKey);
    }

    /**
     * Sets the private key (d) used for GOST signature generation.
     *
     * @param privateKey the private key to set
     */
    public void setPrivateKey(ModifiableBigInteger privateKey) {
        this.privateKey = privateKey;
    }

    /**
     * Gets the nonce (k) used in GOST signature generation.
     *
     * @return the nonce value
     */
    public ModifiableBigInteger getNonce() {
        return nonce;
    }

    /**
     * Sets the nonce (k) used in GOST signature generation.
     *
     * @param nonce the nonce value to set as BigInteger
     */
    public void setNonce(BigInteger nonce) {
        this.nonce = ModifiableVariableFactory.safelySetValue(this.nonce, nonce);
    }

    /**
     * Sets the nonce (k) used in GOST signature generation.
     *
     * @param nonce the nonce value to set
     */
    public void setNonce(ModifiableBigInteger nonce) {
        this.nonce = nonce;
    }

    /**
     * Gets the inverse nonce (k^-1) used in GOST signature generation.
     *
     * @return the inverse nonce value
     */
    public ModifiableBigInteger getInverseNonce() {
        return inverseNonce;
    }

    /**
     * Sets the inverse nonce (k^-1) used in GOST signature generation.
     *
     * @param inverseNonce the inverse nonce value to set as BigInteger
     */
    public void setInverseNonce(BigInteger inverseNonce) {
        this.inverseNonce =
                ModifiableVariableFactory.safelySetValue(this.inverseNonce, inverseNonce);
    }

    /**
     * Sets the inverse nonce (k^-1) used in GOST signature generation.
     *
     * @param inverseNonce the inverse nonce value to set
     */
    public void setInverseNonce(ModifiableBigInteger inverseNonce) {
        this.inverseNonce = inverseNonce;
    }

    /**
     * Gets the x coordinate of k*G point.
     *
     * @return the x coordinate
     */
    public ModifiableBigInteger getrX() {
        return rX;
    }

    /**
     * Sets the x coordinate of k*G point.
     *
     * @param rX the x coordinate to set as BigInteger
     */
    public void setrX(BigInteger rX) {
        this.rX = ModifiableVariableFactory.safelySetValue(this.rX, rX);
    }

    /**
     * Sets the x coordinate of k*G point.
     *
     * @param rX the x coordinate to set
     */
    public void setrX(ModifiableBigInteger rX) {
        this.rX = rX;
    }

    /**
     * Gets the s component of the GOST signature.
     *
     * @return the s component
     */
    public ModifiableBigInteger getS() {
        return s;
    }

    /**
     * Sets the s component of the GOST signature.
     *
     * @param s the s component to set as BigInteger
     */
    public void setS(BigInteger s) {
        this.s = ModifiableVariableFactory.safelySetValue(this.s, s);
    }

    /**
     * Sets the s component of the GOST signature.
     *
     * @param s the s component to set
     */
    public void setS(ModifiableBigInteger s) {
        this.s = s;
    }
}
