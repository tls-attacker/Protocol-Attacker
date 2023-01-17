package de.rub.nds.protocol.crypto.signature;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import java.math.BigInteger;

public abstract class SignatureComputations {

    private ModifiableByteArray signatureBytes;

    private ModifiableByteArray toBeSignedBytes;

    private ModifiableByteArray digestBytes;

    private Boolean signatureValid;

    public SignatureComputations() {
    }

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
        ModifiableVariableFactory.safelySetValue(this.signatureBytes, signatureBytes);
    }

    public ModifiableByteArray getToBeSignedBytes() {
        return toBeSignedBytes;
    }

    public void setToBeSignedBytes(ModifiableByteArray toBeSignedBytes) {
        this.toBeSignedBytes = toBeSignedBytes;
    }

    public void setToBeSignedBytes(byte[] toBeSignedBytes) {
        ModifiableVariableFactory.safelySetValue(this.toBeSignedBytes, toBeSignedBytes);
    }

    public ModifiableByteArray getDigestBytes() {
        return digestBytes;
    }

    public void setDigestBytes(ModifiableByteArray digestBytes) {
        this.digestBytes = digestBytes;
    }

    public void setDigestBytes(byte[] digestBytes) {
        ModifiableVariableFactory.safelySetValue(this.digestBytes, digestBytes);
    }

}
