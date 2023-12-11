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

public class RsaSsaPssSignatureComputations extends SignatureComputations {

    private ModifiableBigInteger privateKey;

    private ModifiableBigInteger modulus;

    private ModifiableByteArray plainToBeSigned;

    private ModifiableByteArray salt;

    /** 0x0000000000000000 | digest | salt */
    private ModifiableByteArray paddedSaltedDigest;

    /** H = Hash(paddedSaltedDigest) */
    private ModifiableByteArray hValue;

    /** PS = emLen - sLen - hLen - 2 zero octets */
    private ModifiableByteArray psValue;

    /** DB = PS | 01 | salt */
    private ModifiableByteArray dbValue;

    /** MGF(hValue) XOR DB */
    private ModifiableByteArray maskedDb;

    /** EM=(maskedValue | H | TF) */
    private ModifiableByteArray emValue;

    /** TF */
    private ModifiableByteArray tfValue;

    private HashAlgorithm hashAlgorithm;

    public RsaSsaPssSignatureComputations() {}

    public ModifiableBigInteger getPrivateKey() {
        return privateKey;
    }

    public void setPaddedSaltedDigest(ModifiableByteArray paddedSaltedDigest) {
        this.paddedSaltedDigest = paddedSaltedDigest;
    }

    public void setPaddedSaltedDigest(byte[] paddedSaltedDigest) {
        this.paddedSaltedDigest =
                ModifiableVariableFactory.safelySetValue(
                        this.paddedSaltedDigest, paddedSaltedDigest);
    }

    public ModifiableByteArray getPaddedSaltedDigest() {
        return paddedSaltedDigest;
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

    public HashAlgorithm getHashAlgorithm() {
        return hashAlgorithm;
    }

    public void setHashAlgorithm(HashAlgorithm hashAlgorithm) {
        this.hashAlgorithm = hashAlgorithm;
    }

    public ModifiableByteArray getSalt() {
        return salt;
    }

    public void setSalt(ModifiableByteArray salt) {
        this.salt = salt;
    }

    public void setSalt(byte[] salt) {
        this.salt = ModifiableVariableFactory.safelySetValue(this.salt, salt);
    }

    public ModifiableByteArray getHValue() {
        return hValue;
    }

    public void setHValue(ModifiableByteArray hValue) {
        this.hValue = hValue;
    }

    public void setHValue(byte[] hValue) {
        this.hValue = ModifiableVariableFactory.safelySetValue(this.hValue, hValue);
    }

    public ModifiableByteArray getDbValue() {
        return dbValue;
    }

    public void setDbValue(ModifiableByteArray dbValue) {
        this.dbValue = dbValue;
    }

    public void setDbValue(byte[] dbValue) {
        this.dbValue = ModifiableVariableFactory.safelySetValue(this.dbValue, dbValue);
    }

    public ModifiableByteArray getMaskedDb() {
        return maskedDb;
    }

    public void setMaskedDb(ModifiableByteArray maskedValue) {
        this.maskedDb = maskedValue;
    }

    public void setMaskedDb(byte[] maskedValue) {
        this.maskedDb = ModifiableVariableFactory.safelySetValue(this.maskedDb, maskedValue);
    }

    public ModifiableByteArray getEmValue() {
        return emValue;
    }

    public void setEmValue(ModifiableByteArray emValue) {
        this.emValue = emValue;
    }

    public void setEmValue(byte[] emValue) {
        this.emValue = ModifiableVariableFactory.safelySetValue(this.emValue, emValue);
    }

    public ModifiableByteArray getTfValue() {
        return tfValue;
    }

    public void setTfValue(ModifiableByteArray tfValue) {
        this.tfValue = tfValue;
    }

    public void setTfValue(byte[] tfValue) {
        this.tfValue = ModifiableVariableFactory.safelySetValue(this.tfValue, tfValue);
    }

    public ModifiableByteArray getPsValue() {
        return psValue;
    }

    public void setPsValue(ModifiableByteArray psValue) {
        this.psValue = psValue;
    }

    public void setPsValue(byte[] psValue) {
        this.psValue = ModifiableVariableFactory.safelySetValue(this.psValue, psValue);
    }
}
