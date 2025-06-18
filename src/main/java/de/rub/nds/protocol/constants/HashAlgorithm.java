/*
 * Protocol-Attacker - A Framework to create Protocol Analysis Tools
 *
 * Copyright 2023-2024 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.protocol.constants;

/**
 * Enumeration of cryptographic hash algorithms with their properties.
 * Provides OID, bit length, security strength, and Java provider name for each algorithm.
 */
public enum HashAlgorithm {
    NONE("1.2.840.113549.2.1", 0, 0, null),
    MD2("1.2.840.113549.2.2", 128, 64, "MD2"),
    MD4("1.2.840.113549.2.4", 128, 64, "MD4"),
    MD5("1.2.840.113549.2.5", 128, 64, "MD5"),
    SHA1("1.3.14.3.2.26", 160, 80, "SHA1"),
    SHA224("2.16.840.1.101.3.4.2.4", 256, 128, "SHA224"),
    SHA256("2.16.840.1.101.3.4.2.1", 256, 128, "SHA256"),
    SHA384("2.16.840.1.101.3.4.2.2", 384, 192, "SHA384"),
    SHA512("2.16.840.1.101.3.4.2.3", 512, 256, "SHA512"),
    SHA512_224("2.16.840.1.101.3.4.2.5", 224, 112, "SHA-512/224"),
    SHA512_256("2.16.840.1.101.3.4.2.6", 256, 128, "SHA-512/256"),
    SM3("1.0.10118.3.0.65", 256, 128, "SM3"),
    SHA3_256("2.16.840.1.101.3.4.2.8", 256, 128, "SHA3-256"),
    GOST_R3411_12("1.2.643.7.1.1.2.2", 256, 128, "GOST3411-2012-256"),
    GOST_R3411_94("1.2.643.2.2.30.0", 256, 128, "GOST3411");

    /** OID of the hash algorithm. */
    private String hashAlgorithmIdentifierOid;

    /** The length of a hash in bits. */
    private int bitLength;

    /** Security strength in bits. */
    private int securityStrength;

    /** Java Security Provider algorithm name. */
    private String javaName;

    HashAlgorithm(
            String hashAlgorithmIdentifierOid,
            int bitStrength,
            int securityStrength,
            String javaName) {
        this.hashAlgorithmIdentifierOid = hashAlgorithmIdentifierOid;
        this.bitLength = bitStrength;
        this.securityStrength = securityStrength;
        this.javaName = javaName;
    }

    /**
     * Returns the Java provider name for this hash algorithm.
     *
     * @return the Java provider name, or null if not applicable
     */
    public String getJavaName() {
        return javaName;
    }

    /**
     * Returns the OID (Object Identifier) of this hash algorithm.
     *
     * @return the OID string
     */
    public String getHashAlgorithmIdentifierOid() {
        return hashAlgorithmIdentifierOid;
    }

    /**
     * Returns the output length of this hash algorithm in bits.
     *
     * @return the bit length of the hash output
     */
    public int getBitLength() {
        return bitLength;
    }

    /**
     * Returns the security strength of this hash algorithm in bits.
     *
     * @return the security strength in bits
     */
    public int getSecurityStrength() {
        return securityStrength;
    }
}
