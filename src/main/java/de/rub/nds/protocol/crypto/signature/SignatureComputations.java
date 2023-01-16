package de.rub.nds.protocol.crypto.signature;

import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;

public abstract class SignatureComputations {

    private ModifiableByteArray signatureBytes;

    private ModifiableByteArray toBeSignedBytes;

    private ModifiableByteArray hashedBytes;

    public SignatureComputations() {
    }

    public ModifiableByteArray getSignatureBytes() {
        return signatureBytes;
    }

    public void setSignatureBytes(ModifiableByteArray signatureBytes) {
        this.signatureBytes = signatureBytes;
    }

    public ModifiableByteArray getToBeSignedBytes() {
        return toBeSignedBytes;
    }

    public void setToBeSignedBytes(ModifiableByteArray toBeSignedBytes) {
        this.toBeSignedBytes = toBeSignedBytes;
    }

    public ModifiableByteArray getHashedBytes() {
        return hashedBytes;
    }

    public void setHashedBytes(ModifiableByteArray hashedBytes) {
        this.hashedBytes = hashedBytes;
    }

}
