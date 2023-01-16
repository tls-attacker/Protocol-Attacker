package de.rub.nds.protocol.crypto.signature;

import de.rub.nds.modifiablevariable.biginteger.ModifiableBigInteger;

public class EcdsaSignatureComputations extends SignatureComputations {

    private ModifiableBigInteger privateKey; //d

    private ModifiableBigInteger nonce; //k
    
    private ModifiableBigInteger inverseNonce; //k^-1

    private ModifiableBigInteger rX; //x coordinate of k*G

    private ModifiableBigInteger s; //s

    public EcdsaSignatureComputations() {
    }

    public ModifiableBigInteger getPrivateKey() {
        return privateKey;
    }

    public void setPrivateKey(ModifiableBigInteger privateKey) {
        this.privateKey = privateKey;
    }

    public ModifiableBigInteger getNonce() {
        return nonce;
    }

    public void setNonce(ModifiableBigInteger nonce) {
        this.nonce = nonce;
    }

    public ModifiableBigInteger getInverseNonce() {
        return inverseNonce;
    }

    public void setInverseNonce(ModifiableBigInteger inverseNonce) {
        this.inverseNonce = inverseNonce;
    }

    public ModifiableBigInteger getrX() {
        return rX;
    }

    public void setrX(ModifiableBigInteger rX) {
        this.rX = rX;
    }

    public ModifiableBigInteger getS() {
        return s;
    }

    public void setS(ModifiableBigInteger s) {
        this.s = s;
    }
}
