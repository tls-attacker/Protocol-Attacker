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

/** No idea if this makes sense, GOST is currently low prio */
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

    public GostSignatureComputations() {}

    public ModifiableByteArray getTruncatedHashBytes() {
        return truncatedHashBytes;
    }

    public void setTruncatedHashBytes(ModifiableByteArray truncatedHashBytes) {
        this.truncatedHashBytes = truncatedHashBytes;
    }

    public void setTruncatedHashBytes(byte[] truncatedHashBytes) {
        ModifiableVariableFactory.safelySetValue(this.truncatedHashBytes, truncatedHashBytes);
    }

    public ModifiableBigInteger getTruncatedHash() {
        return truncatedHash;
    }

    public void setTruncatedHash(ModifiableBigInteger truncatedHash) {
        this.truncatedHash = truncatedHash;
    }

    public void setTruncatedHash(BigInteger truncatedHash) {
        ModifiableVariableFactory.safelySetValue(this.truncatedHash, truncatedHash);
    }

    public NamedEllipticCurveParameters getEcParameters() {
        return ecParameters;
    }

    public void setEcParameters(NamedEllipticCurveParameters ecParameters) {
        this.ecParameters = ecParameters;
    }

    public HashAlgorithm getHashAlgorithm() {
        return hashAlgorithm;
    }

    public void setHashAlgorithm(HashAlgorithm hashAlgorithm) {
        this.hashAlgorithm = hashAlgorithm;
    }

    public ModifiableBigInteger getPrivateKey() {
        return privateKey;
    }

    public void setPrivateKey(BigInteger privateKey) {
        ModifiableVariableFactory.safelySetValue(this.privateKey, privateKey);
    }

    public void setPrivateKey(ModifiableBigInteger privateKey) {
        this.privateKey = privateKey;
    }

    public ModifiableBigInteger getNonce() {
        return nonce;
    }

    public void setNonce(BigInteger nonce) {
        ModifiableVariableFactory.safelySetValue(this.nonce, nonce);
    }

    public void setNonce(ModifiableBigInteger nonce) {
        this.nonce = nonce;
    }

    public ModifiableBigInteger getInverseNonce() {
        return inverseNonce;
    }

    public void setInverseNonce(BigInteger inverseNonce) {
        ModifiableVariableFactory.safelySetValue(this.inverseNonce, inverseNonce);
    }

    public void setInverseNonce(ModifiableBigInteger inverseNonce) {
        this.inverseNonce = inverseNonce;
    }

    public ModifiableBigInteger getrX() {
        return rX;
    }

    public void setrX(BigInteger rX) {
        ModifiableVariableFactory.safelySetValue(this.rX, rX);
    }

    public void setrX(ModifiableBigInteger rX) {
        this.rX = rX;
    }

    public ModifiableBigInteger getS() {
        return s;
    }

    public void setS(BigInteger s) {
        ModifiableVariableFactory.safelySetValue(this.s, s);
    }

    public void setS(ModifiableBigInteger s) {
        this.s = s;
    }
}
