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

    /** Constructs a new RsaPkcs1SignatureComputations instance. */
    public RsaPkcs1SignatureComputations() {}

    /**
     * Gets the RSA private key used for PKCS#1 signature generation.
     *
     * @return the private key
     */
    public ModifiableBigInteger getPrivateKey() {
        return privateKey;
    }

    /**
     * Sets the RSA private key used for PKCS#1 signature generation.
     *
     * @param privateKey the private key to set
     */
    public void setPrivateKey(ModifiableBigInteger privateKey) {
        this.privateKey = privateKey;
    }

    /**
     * Sets the RSA private key used for PKCS#1 signature generation.
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
     * Gets the PKCS#1 padding bytes.
     *
     * @return the padding bytes
     */
    public ModifiableByteArray getPadding() {
        return padding;
    }

    /**
     * Sets the PKCS#1 padding bytes.
     *
     * @param padding the padding bytes to set
     */
    public void setPadding(ModifiableByteArray padding) {
        this.padding = padding;
    }

    /**
     * Sets the PKCS#1 padding bytes.
     *
     * @param padding the padding bytes to set as byte array
     */
    public void setPadding(byte[] padding) {
        this.padding = ModifiableVariableFactory.safelySetValue(this.padding, padding);
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
     * Gets the DER-encoded digest value.
     *
     * @return the DER-encoded digest
     */
    public ModifiableByteArray getDerEncodedDigest() {
        return derEncodedDigest;
    }

    /**
     * Sets the DER-encoded digest value.
     *
     * @param derEncodedDigest the DER-encoded digest to set
     */
    public void setDerEncodedDigest(byte[] derEncodedDigest) {
        this.derEncodedDigest =
                ModifiableVariableFactory.safelySetValue(this.derEncodedDigest, derEncodedDigest);
    }

    /**
     * Gets the hash algorithm used for PKCS#1 signature computation.
     *
     * @return the hash algorithm
     */
    public HashAlgorithm getHashAlgorithm() {
        return hashAlgorithm;
    }

    /**
     * Sets the hash algorithm used for PKCS#1 signature computation.
     *
     * @param hashAlgorithm the hash algorithm to set
     */
    public void setHashAlgorithm(HashAlgorithm hashAlgorithm) {
        this.hashAlgorithm = hashAlgorithm;
    }
}
