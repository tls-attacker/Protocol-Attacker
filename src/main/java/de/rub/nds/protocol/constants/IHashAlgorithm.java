package de.rub.nds.protocol.constants;

public interface IHashAlgorithm {

    public int getBitLength();

    public int getSecurityStrength();

    public byte[] computeHash(byte[] data);
}
