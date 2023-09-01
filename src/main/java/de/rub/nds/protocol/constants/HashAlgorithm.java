/*
 * Protocol-Attacker - A framework to create protocol analysis tools
 *
 * Copyright 2023-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.protocol.constants;

/** Metadata for hash algorithms. */
public enum HashAlgorithm {
    NONE(null, 0),
    MD2("1.2.840.113549.2.2", 128),
    MD4("1.2.840.113549.2.4", 128),
    MD5("1.2.840.113549.2.5", 128),
    SHA1("1.3.14.3.2.26", 160),
    SHA256("2.16.840.1.101.3.4.2.1", 256),
    SHA384("2.16.840.1.101.3.4.2.2", 384),
    SHA512("2.16.840.1.101.3.4.2.3", 512),
    SHA512_224("2.16.840.1.101.3.4.2.5", 224),
    SM3("1.0.10118.3.0.65", 256),
    SHA3_256("2.16.840.1.101.3.4.2.8", 256);

    /** OID of the hash algorithm. */
    private String hashAlgorithmIdentifierOid;
    /** The length of a hash */
    private int bitLength;

    private int secruityStrength;

    private HashAlgorithm(String hashAlgorithmIdentifierOid, int bitStrength) {
        this.hashAlgorithmIdentifierOid = hashAlgorithmIdentifierOid;
        this.bitLength = bitStrength;
    }

    public String getHashAlgorithmIdentifierOid() {
        return hashAlgorithmIdentifierOid;
    }

    public int getBitLength() {
        return bitLength;
    }

    public int getSecurityStrength() {
        return bitLength / 2; // This is true right now, might change in the future
    }
}
