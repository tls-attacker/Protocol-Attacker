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
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;

public abstract class SignatureComputations {

    private ModifiableByteArray signatureBytes;

    private ModifiableByteArray toBeSignedBytes;

    private ModifiableByteArray digestBytes;

    private Boolean signatureValid;

    public SignatureComputations() {}

    public Boolean getSignatureValid() {
        return signatureValid;
    }

    public void setSignatureValid(Boolean signatureValid) {
        this.signatureValid = signatureValid;
    }

    public ModifiableByteArray getSignatureBytes() {
        return signatureBytes;
    }

    public void setSignatureBytes(ModifiableByteArray signatureBytes) {
        this.signatureBytes = signatureBytes;
    }

    public void setSignatureBytes(byte[] signatureBytes) {
        this.signatureBytes =
                ModifiableVariableFactory.safelySetValue(this.signatureBytes, signatureBytes);
    }

    public ModifiableByteArray getToBeSignedBytes() {
        return toBeSignedBytes;
    }

    public void setToBeSignedBytes(ModifiableByteArray toBeSignedBytes) {
        this.toBeSignedBytes = toBeSignedBytes;
    }

    public void setToBeSignedBytes(byte[] toBeSignedBytes) {
        this.toBeSignedBytes =
                ModifiableVariableFactory.safelySetValue(this.toBeSignedBytes, toBeSignedBytes);
    }

    public ModifiableByteArray getDigestBytes() {
        return digestBytes;
    }

    public void setDigestBytes(ModifiableByteArray digestBytes) {
        this.digestBytes = digestBytes;
    }

    public void setDigestBytes(byte[] digestBytes) {
        this.digestBytes = ModifiableVariableFactory.safelySetValue(this.digestBytes, digestBytes);
    }
}
