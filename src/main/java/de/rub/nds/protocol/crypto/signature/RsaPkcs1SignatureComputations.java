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
import java.math.BigInteger;

public class RsaPkcs1SignatureComputations extends SignatureComputations {

    private ModifiableBigInteger privateKey;

    private ModifiableBigInteger modulus;

    private ModifiableByteArray padding;

    private ModifiableByteArray plainToBeSigned;

    private ModifiableByteArray derEncodedDigest;

    private HashAlgorithm hashAlgorithm;

    public RsaPkcs1SignatureComputations() {}

    public ModifiableBigInteger getPrivateKey() {
        return privateKey;
    }

    public void setPrivateKey(ModifiableBigInteger privateKey) {
        this.privateKey = privateKey;
    }

    public void setPrivateKey(BigInteger privateKey) {
        this.privateKey = ModifiableVariableFactory.safelySetValue(this.privateKey, privateKey);
    }

    public ModifiableBigInteger getModulus() {
        return modulus;
    }

    public void setModulus(ModifiableBigInteger modulus) {
        this.modulus = modulus;
    }

    public void setModulus(BigInteger modulus) {
        this.modulus = ModifiableVariableFactory.safelySetValue(this.modulus, modulus);
    }

    public ModifiableByteArray getPadding() {
        return padding;
    }

    public void setPadding(ModifiableByteArray padding) {
        this.padding = padding;
    }

    public void setPadding(byte[] padding) {
        this.padding = ModifiableVariableFactory.safelySetValue(this.padding, padding);
    }

    public ModifiableByteArray getPlainToBeSigned() {
        return plainToBeSigned;
    }

    public void setPlainToBeSigned(ModifiableByteArray plainToBeSigned) {
        this.plainToBeSigned = plainToBeSigned;
    }

    public void setPlainToBeSigned(byte[] plainToBeSigned) {
        this.plainToBeSigned =
                ModifiableVariableFactory.safelySetValue(this.plainToBeSigned, plainToBeSigned);
    }

    public ModifiableByteArray getDerEncodedDigest() {
        return derEncodedDigest;
    }

    public void setDerEncodedDigest(byte[] derEncodedDigest) {
        this.derEncodedDigest =
                ModifiableVariableFactory.safelySetValue(this.derEncodedDigest, derEncodedDigest);
    }

    public HashAlgorithm getHashAlgorithm() {
        return hashAlgorithm;
    }

    public void setHashAlgorithm(HashAlgorithm hashAlgorithm) {
        this.hashAlgorithm = hashAlgorithm;
    }
}
