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

    /** Constructs a new RsaSsaPssSignatureComputations instance. */
    public RsaSsaPssSignatureComputations() {}

    /**
     * Gets the RSA private key used for RSA-PSS signature generation.
     *
     * @return the private key
     */
    public ModifiableBigInteger getPrivateKey() {
        return privateKey;
    }

    /**
     * Sets the padded salted digest value used in RSA-PSS.
     *
     * @param paddedSaltedDigest the padded salted digest to set
     */
    public void setPaddedSaltedDigest(ModifiableByteArray paddedSaltedDigest) {
        this.paddedSaltedDigest = paddedSaltedDigest;
    }

    /**
     * Sets the padded salted digest value used in RSA-PSS.
     *
     * @param paddedSaltedDigest the padded salted digest to set as byte array
     */
    public void setPaddedSaltedDigest(byte[] paddedSaltedDigest) {
        this.paddedSaltedDigest =
                ModifiableVariableFactory.safelySetValue(
                        this.paddedSaltedDigest, paddedSaltedDigest);
    }

    /**
     * Gets the padded salted digest value (0x0000000000000000 | digest | salt).
     *
     * @return the padded salted digest
     */
    public ModifiableByteArray getPaddedSaltedDigest() {
        return paddedSaltedDigest;
    }

    /**
     * Sets the RSA private key used for RSA-PSS signature generation.
     *
     * @param privateKey the private key to set
     */
    public void setPrivateKey(ModifiableBigInteger privateKey) {
        this.privateKey = privateKey;
    }

    /**
     * Sets the RSA private key used for RSA-PSS signature generation.
     *
     * @param privateKey the private key to set as BigInteger
     */
    public void setPrivateKey(BigInteger privateKey) {
        this.privateKey = ModifiableVariableFactory.safelySetValue(this.privateKey, privateKey);
    }

    /**
     * Gets the RSA modulus.
     *
     * @return the RSA modulus
     */
    public ModifiableBigInteger getModulus() {
        return modulus;
    }

    /**
     * Sets the RSA modulus.
     *
     * @param modulus the RSA modulus to set
     */
    public void setModulus(ModifiableBigInteger modulus) {
        this.modulus = modulus;
    }

    /**
     * Sets the RSA modulus.
     *
     * @param modulus the RSA modulus to set as BigInteger
     */
    public void setModulus(BigInteger modulus) {
        this.modulus = ModifiableVariableFactory.safelySetValue(this.modulus, modulus);
    }

    /**
     * Gets the plain data to be signed.
     *
     * @return the plain data to be signed
     */
    public ModifiableByteArray getPlainToBeSigned() {
        return plainToBeSigned;
    }

    /**
     * Sets the plain data to be signed.
     *
     * @param plainToBeSigned the plain data to be signed
     */
    public void setPlainToBeSigned(ModifiableByteArray plainToBeSigned) {
        this.plainToBeSigned = plainToBeSigned;
    }

    /**
     * Sets the plain data to be signed.
     *
     * @param plainToBeSigned the plain data to be signed as byte array
     */
    public void setPlainToBeSigned(byte[] plainToBeSigned) {
        this.plainToBeSigned =
                ModifiableVariableFactory.safelySetValue(this.plainToBeSigned, plainToBeSigned);
    }

    /**
     * Gets the hash algorithm used for RSA-PSS signature computation.
     *
     * @return the hash algorithm
     */
    public HashAlgorithm getHashAlgorithm() {
        return hashAlgorithm;
    }

    /**
     * Sets the hash algorithm used for RSA-PSS signature computation.
     *
     * @param hashAlgorithm the hash algorithm to set
     */
    public void setHashAlgorithm(HashAlgorithm hashAlgorithm) {
        this.hashAlgorithm = hashAlgorithm;
    }

    /**
     * Gets the salt value used in RSA-PSS.
     *
     * @return the salt value
     */
    public ModifiableByteArray getSalt() {
        return salt;
    }

    /**
     * Sets the salt value used in RSA-PSS.
     *
     * @param salt the salt value to set
     */
    public void setSalt(ModifiableByteArray salt) {
        this.salt = salt;
    }

    /**
     * Sets the salt value used in RSA-PSS.
     *
     * @param salt the salt value to set as byte array
     */
    public void setSalt(byte[] salt) {
        this.salt = ModifiableVariableFactory.safelySetValue(this.salt, salt);
    }

    /**
     * Gets the H value (Hash of paddedSaltedDigest) in RSA-PSS.
     *
     * @return the H value
     */
    public ModifiableByteArray getHValue() {
        return hValue;
    }

    /**
     * Sets the H value (Hash of paddedSaltedDigest) in RSA-PSS.
     *
     * @param hValue the H value to set
     */
    public void setHValue(ModifiableByteArray hValue) {
        this.hValue = hValue;
    }

    /**
     * Sets the H value (Hash of paddedSaltedDigest) in RSA-PSS.
     *
     * @param hValue the H value to set as byte array
     */
    public void setHValue(byte[] hValue) {
        this.hValue = ModifiableVariableFactory.safelySetValue(this.hValue, hValue);
    }

    /**
     * Gets the DB value (PS | 01 | salt) in RSA-PSS.
     *
     * @return the DB value
     */
    public ModifiableByteArray getDbValue() {
        return dbValue;
    }

    /**
     * Sets the DB value (PS | 01 | salt) in RSA-PSS.
     *
     * @param dbValue the DB value to set
     */
    public void setDbValue(ModifiableByteArray dbValue) {
        this.dbValue = dbValue;
    }

    /**
     * Sets the DB value (PS | 01 | salt) in RSA-PSS.
     *
     * @param dbValue the DB value to set as byte array
     */
    public void setDbValue(byte[] dbValue) {
        this.dbValue = ModifiableVariableFactory.safelySetValue(this.dbValue, dbValue);
    }

    /**
     * Gets the masked DB value (MGF(hValue) XOR DB) in RSA-PSS.
     *
     * @return the masked DB value
     */
    public ModifiableByteArray getMaskedDb() {
        return maskedDb;
    }

    /**
     * Sets the masked DB value (MGF(hValue) XOR DB) in RSA-PSS.
     *
     * @param maskedValue the masked DB value to set
     */
    public void setMaskedDb(ModifiableByteArray maskedValue) {
        this.maskedDb = maskedValue;
    }

    /**
     * Sets the masked DB value (MGF(hValue) XOR DB) in RSA-PSS.
     *
     * @param maskedValue the masked DB value to set as byte array
     */
    public void setMaskedDb(byte[] maskedValue) {
        this.maskedDb = ModifiableVariableFactory.safelySetValue(this.maskedDb, maskedValue);
    }

    /**
     * Gets the EM value (maskedValue | H | TF) in RSA-PSS.
     *
     * @return the EM value
     */
    public ModifiableByteArray getEmValue() {
        return emValue;
    }

    /**
     * Sets the EM value (maskedValue | H | TF) in RSA-PSS.
     *
     * @param emValue the EM value to set
     */
    public void setEmValue(ModifiableByteArray emValue) {
        this.emValue = emValue;
    }

    /**
     * Sets the EM value (maskedValue | H | TF) in RSA-PSS.
     *
     * @param emValue the EM value to set as byte array
     */
    public void setEmValue(byte[] emValue) {
        this.emValue = ModifiableVariableFactory.safelySetValue(this.emValue, emValue);
    }

    /**
     * Gets the TF (trailer field) value in RSA-PSS.
     *
     * @return the TF value
     */
    public ModifiableByteArray getTfValue() {
        return tfValue;
    }

    /**
     * Sets the TF (trailer field) value in RSA-PSS.
     *
     * @param tfValue the TF value to set
     */
    public void setTfValue(ModifiableByteArray tfValue) {
        this.tfValue = tfValue;
    }

    /**
     * Sets the TF (trailer field) value in RSA-PSS.
     *
     * @param tfValue the TF value to set as byte array
     */
    public void setTfValue(byte[] tfValue) {
        this.tfValue = ModifiableVariableFactory.safelySetValue(this.tfValue, tfValue);
    }

    /**
     * Gets the PS value (padding string: emLen - sLen - hLen - 2 zero octets).
     *
     * @return the PS value
     */
    public ModifiableByteArray getPsValue() {
        return psValue;
    }

    /**
     * Sets the PS value (padding string: emLen - sLen - hLen - 2 zero octets).
     *
     * @param psValue the PS value to set
     */
    public void setPsValue(ModifiableByteArray psValue) {
        this.psValue = psValue;
    }

    /**
     * Sets the PS value (padding string: emLen - sLen - hLen - 2 zero octets).
     *
     * @param psValue the PS value to set as byte array
     */
    public void setPsValue(byte[] psValue) {
        this.psValue = ModifiableVariableFactory.safelySetValue(this.psValue, psValue);
    }
}
