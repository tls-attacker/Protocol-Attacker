/*
 * Protocol-Attacker - A framework to create protocol analysis tools
 *
 * Copyright 2023-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.protocol.crypto.signature;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.biginteger.ModifiableBigInteger;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import java.math.BigInteger;

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

    public DsaSignatureComputations() {}

    public ModifiableBigInteger getPrivateKey() {
        return privateKey;
    }

    public void setPrivateKey(ModifiableBigInteger privateKey) {
        this.privateKey = privateKey;
    }

    public void setPrivateKey(BigInteger privateKey) {
        ModifiableVariableFactory.safelySetValue(this.privateKey, privateKey);
    }

    public ModifiableBigInteger getQ() {
        return q;
    }

    public void setQ(ModifiableBigInteger q) {
        this.q = q;
    }

    public void setQ(BigInteger q) {
        ModifiableVariableFactory.safelySetValue(this.q, q);
    }

    public ModifiableBigInteger getR() {
        return r;
    }

    public void setR(ModifiableBigInteger r) {
        this.r = r;
    }

    public void setR(BigInteger r) {
        ModifiableVariableFactory.safelySetValue(this.r, r);
    }

    public ModifiableBigInteger getS() {
        return s;
    }

    public void setS(ModifiableBigInteger s) {
        this.s = s;
    }

    public void setS(BigInteger s) {
        ModifiableVariableFactory.safelySetValue(this.s, s);
    }

    public ModifiableBigInteger getInverseNonce() {
        return inverseNonce;
    }

    public void setInverseNonce(ModifiableBigInteger inverseNonce) {
        this.inverseNonce = inverseNonce;
    }

    public void setInverseNonce(BigInteger inverseNonce) {
        ModifiableVariableFactory.safelySetValue(this.inverseNonce, inverseNonce);
    }

    public ModifiableBigInteger getXr() {
        return xr;
    }

    public void setXr(ModifiableBigInteger xr) {
        this.xr = xr;
    }

    public void setXr(BigInteger xr) {
        ModifiableVariableFactory.safelySetValue(this.xr, xr);
    }

    public ModifiableBigInteger getG() {
        return g;
    }

    public void setG(ModifiableBigInteger g) {
        this.g = g;
    }

    public void setG(BigInteger g) {
        ModifiableVariableFactory.safelySetValue(this.g, g);
    }

    public ModifiableBigInteger getP() {
        return p;
    }

    public void setP(ModifiableBigInteger p) {
        this.p = p;
    }

    public void setP(BigInteger p) {
        ModifiableVariableFactory.safelySetValue(this.p, p);
    }

    public ModifiableBigInteger getNonce() {
        return nonce;
    }

    public void setNonce(ModifiableBigInteger nonce) {
        this.nonce = nonce;
    }

    public void setNonce(BigInteger nonce) {
        ModifiableVariableFactory.safelySetValue(this.nonce, nonce);
    }

    public ModifiableByteArray getTruncatedHashBytes() {
        return truncatedHashBytes;
    }

    public void setTruncatedHashBytes(ModifiableByteArray truncatedHashBytes) {
        this.truncatedHashBytes = truncatedHashBytes;
    }

    public void setTruncatedHashBytes(byte[] truncatedHashBytes) {
        ModifiableVariableFactory.safelySetValue(this.truncatedHashBytes, truncatedHashBytes);
    }
}
