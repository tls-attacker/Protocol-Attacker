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
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;

/**
 * Abstract base class for signature computation implementations. Provides common fields and methods
 * for various signature algorithms.
 */
public abstract class SignatureComputations {

    private ModifiableByteArray signatureBytes;

    private ModifiableByteArray toBeSignedBytes;

    private ModifiableByteArray digestBytes;

    private Boolean signatureValid;

    /** Constructs a new SignatureComputations instance. */
    public SignatureComputations() {}

    /**
     * Gets the signature validity status.
     *
     * @return true if the signature is valid, false otherwise, or null if not set
     */
    public Boolean getSignatureValid() {
        return signatureValid;
    }

    /**
     * Sets the signature validity status.
     *
     * @param signatureValid the validity status to set
     */
    public void setSignatureValid(Boolean signatureValid) {
        this.signatureValid = signatureValid;
    }

    /**
     * Gets the computed signature bytes.
     *
     * @return the signature bytes
     */
    public ModifiableByteArray getSignatureBytes() {
        return signatureBytes;
    }

    /**
     * Sets the signature bytes.
     *
     * @param signatureBytes the signature bytes to set
     */
    public void setSignatureBytes(ModifiableByteArray signatureBytes) {
        this.signatureBytes = signatureBytes;
    }

    /**
     * Sets the signature bytes.
     *
     * @param signatureBytes the signature bytes to set as byte array
     */
    public void setSignatureBytes(byte[] signatureBytes) {
        this.signatureBytes =
                ModifiableVariableFactory.safelySetValue(this.signatureBytes, signatureBytes);
    }

    /**
     * Gets the data to be signed.
     *
     * @return the data to be signed
     */
    public ModifiableByteArray getToBeSignedBytes() {
        return toBeSignedBytes;
    }

    /**
     * Sets the data to be signed.
     *
     * @param toBeSignedBytes the data to be signed
     */
    public void setToBeSignedBytes(ModifiableByteArray toBeSignedBytes) {
        this.toBeSignedBytes = toBeSignedBytes;
    }

    /**
     * Sets the data to be signed.
     *
     * @param toBeSignedBytes the data to be signed as byte array
     */
    public void setToBeSignedBytes(byte[] toBeSignedBytes) {
        this.toBeSignedBytes =
                ModifiableVariableFactory.safelySetValue(this.toBeSignedBytes, toBeSignedBytes);
    }

    /**
     * Gets the digest (hash) bytes of the data to be signed.
     *
     * @return the digest bytes
     */
    public ModifiableByteArray getDigestBytes() {
        return digestBytes;
    }

    /**
     * Sets the digest (hash) bytes of the data to be signed.
     *
     * @param digestBytes the digest bytes to set
     */
    public void setDigestBytes(ModifiableByteArray digestBytes) {
        this.digestBytes = digestBytes;
    }

    /**
     * Sets the digest (hash) bytes of the data to be signed.
     *
     * @param digestBytes the digest bytes to set as byte array
     */
    public void setDigestBytes(byte[] digestBytes) {
        this.digestBytes = ModifiableVariableFactory.safelySetValue(this.digestBytes, digestBytes);
    }
}
