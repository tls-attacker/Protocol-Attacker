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
import java.math.BigInteger;

/**
 * Computation container for DSA (Digital Signature Algorithm) signatures. Stores parameters p, q,
 * g, private key x, nonce k, and signature components r and s.
 */
public class DsaSignatureComputations extends SignatureComputations {

    private ModifiableBigInteger privateKey;
    private ModifiableBigInteger q;
    private ModifiableBigInteger g;
    private ModifiableBigInteger p;
    private ModifiableBigInteger r;
    private ModifiableBigInteger inverseNonce; // k^-1
    private ModifiableBigInteger s; // s = k^-1 * (H(m) + xr)
    private ModifiableBigInteger xr;
    private ModifiableBigInteger nonce; // k
    private ModifiableByteArray truncatedHashBytes;

    /** Constructs a new DsaSignatureComputations instance. */
    public DsaSignatureComputations() {}

    /**
     * Gets the DSA private key.
     *
     * @return the private key
     */
    public ModifiableBigInteger getPrivateKey() {
        return privateKey;
    }

    /**
     * Sets the DSA private key.
     *
     * @param privateKey the private key to set
     */
    public void setPrivateKey(ModifiableBigInteger privateKey) {
        this.privateKey = privateKey;
    }

    /**
     * Sets the DSA private key.
     *
     * @param privateKey the private key to set as BigInteger
     */
    public void setPrivateKey(BigInteger privateKey) {
        this.privateKey = ModifiableVariableFactory.safelySetValue(this.privateKey, privateKey);
    }

    /**
     * Gets the DSA parameter q (prime divisor).
     *
     * @return the q parameter
     */
    public ModifiableBigInteger getQ() {
        return q;
    }

    /**
     * Sets the DSA parameter q (prime divisor).
     *
     * @param q the q parameter to set
     */
    public void setQ(ModifiableBigInteger q) {
        this.q = q;
    }

    /**
     * Sets the DSA parameter q (prime divisor).
     *
     * @param q the q parameter to set as BigInteger
     */
    public void setQ(BigInteger q) {
        this.q = ModifiableVariableFactory.safelySetValue(this.q, q);
    }

    /**
     * Gets the r component of the DSA signature.
     *
     * @return the r component
     */
    public ModifiableBigInteger getR() {
        return r;
    }

    /**
     * Sets the r component of the DSA signature.
     *
     * @param r the r component to set
     */
    public void setR(ModifiableBigInteger r) {
        this.r = r;
    }

    /**
     * Sets the r component of the DSA signature.
     *
     * @param r the r component to set as BigInteger
     */
    public void setR(BigInteger r) {
        this.r = ModifiableVariableFactory.safelySetValue(this.r, r);
    }

    /**
     * Gets the s component of the DSA signature (s = k^-1 * (H(m) + xr)).
     *
     * @return the s component
     */
    public ModifiableBigInteger getS() {
        return s;
    }

    /**
     * Sets the s component of the DSA signature (s = k^-1 * (H(m) + xr)).
     *
     * @param s the s component to set
     */
    public void setS(ModifiableBigInteger s) {
        this.s = s;
    }

    /**
     * Sets the s component of the DSA signature (s = k^-1 * (H(m) + xr)).
     *
     * @param s the s component to set as BigInteger
     */
    public void setS(BigInteger s) {
        this.s = ModifiableVariableFactory.safelySetValue(this.s, s);
    }

    /**
     * Gets the inverse nonce (k^-1) used in DSA signature generation.
     *
     * @return the inverse nonce
     */
    public ModifiableBigInteger getInverseNonce() {
        return inverseNonce;
    }

    /**
     * Sets the inverse nonce (k^-1) used in DSA signature generation.
     *
     * @param inverseNonce the inverse nonce to set
     */
    public void setInverseNonce(ModifiableBigInteger inverseNonce) {
        this.inverseNonce = inverseNonce;
    }

    /**
     * Sets the inverse nonce (k^-1) used in DSA signature generation.
     *
     * @param inverseNonce the inverse nonce to set as BigInteger
     */
    public void setInverseNonce(BigInteger inverseNonce) {
        this.inverseNonce =
                ModifiableVariableFactory.safelySetValue(this.inverseNonce, inverseNonce);
    }

    /**
     * Gets the xr value (private key * r) used in DSA signature computation.
     *
     * @return the xr value
     */
    public ModifiableBigInteger getXr() {
        return xr;
    }

    /**
     * Sets the xr value (private key * r) used in DSA signature computation.
     *
     * @param xr the xr value to set
     */
    public void setXr(ModifiableBigInteger xr) {
        this.xr = xr;
    }

    /**
     * Sets the xr value (private key * r) used in DSA signature computation.
     *
     * @param xr the xr value to set as BigInteger
     */
    public void setXr(BigInteger xr) {
        this.xr = ModifiableVariableFactory.safelySetValue(this.xr, xr);
    }

    /**
     * Gets the DSA parameter g (generator).
     *
     * @return the g parameter
     */
    public ModifiableBigInteger getG() {
        return g;
    }

    /**
     * Sets the DSA parameter g (generator).
     *
     * @param g the g parameter to set
     */
    public void setG(ModifiableBigInteger g) {
        this.g = g;
    }

    /**
     * Sets the DSA parameter g (generator).
     *
     * @param g the g parameter to set as BigInteger
     */
    public void setG(BigInteger g) {
        this.g = ModifiableVariableFactory.safelySetValue(this.g, g);
    }

    /**
     * Gets the DSA parameter p (prime modulus).
     *
     * @return the p parameter
     */
    public ModifiableBigInteger getP() {
        return p;
    }

    /**
     * Sets the DSA parameter p (prime modulus).
     *
     * @param p the p parameter to set
     */
    public void setP(ModifiableBigInteger p) {
        this.p = p;
    }

    /**
     * Sets the DSA parameter p (prime modulus).
     *
     * @param p the p parameter to set as BigInteger
     */
    public void setP(BigInteger p) {
        this.p = ModifiableVariableFactory.safelySetValue(this.p, p);
    }

    /**
     * Gets the nonce (k) used in DSA signature generation.
     *
     * @return the nonce
     */
    public ModifiableBigInteger getNonce() {
        return nonce;
    }

    /**
     * Sets the nonce (k) used in DSA signature generation.
     *
     * @param nonce the nonce to set
     */
    public void setNonce(ModifiableBigInteger nonce) {
        this.nonce = nonce;
    }

    /**
     * Sets the nonce (k) used in DSA signature generation.
     *
     * @param nonce the nonce to set as BigInteger
     */
    public void setNonce(BigInteger nonce) {
        this.nonce = ModifiableVariableFactory.safelySetValue(this.nonce, nonce);
    }

    /**
     * Gets the truncated hash bytes used in DSA computation.
     *
     * @return the truncated hash bytes
     */
    public ModifiableByteArray getTruncatedHashBytes() {
        return truncatedHashBytes;
    }

    /**
     * Sets the truncated hash bytes used in DSA computation.
     *
     * @param truncatedHashBytes the truncated hash bytes to set
     */
    public void setTruncatedHashBytes(ModifiableByteArray truncatedHashBytes) {
        this.truncatedHashBytes = truncatedHashBytes;
    }

    /**
     * Sets the truncated hash bytes used in DSA computation.
     *
     * @param truncatedHashBytes the truncated hash bytes to set as byte array
     */
    public void setTruncatedHashBytes(byte[] truncatedHashBytes) {
        this.truncatedHashBytes =
                ModifiableVariableFactory.safelySetValue(
                        this.truncatedHashBytes, truncatedHashBytes);
    }
}
