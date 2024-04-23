/*
 * Protocol-Attacker - A Framework to create Protocol Analysis Tools
 *
 * Copyright 2023-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.protocol.constants;

/** Metadata for hash algorithms. */
public enum MacAlgorithm {
    NONE(0, 0, null),
    HMAC_MD5(128, 64, "HmacMD5"),
    HMAC_SHA1(160, 80, "HmacSHA1"),
    HMAC_SHA256(256, 128, "HmacSHA256"),
    HMAC_SHA384(384, 192, "HmacSHA384"),
    HMAC_SHA512(512, 256, "HmacSHA512"),
    HMAC_SHA512_224(224, 112, "HmacSHA512/224"),
    HMAC_SHA512_256(256, 128, "HmacSHA512/256");    
    
    /** The length of a hash */
    private int bitLength;

    private int securityStrength;

    private String javaName;

    private MacAlgorithm(
            int bitStrength,
            int securityStrength,
            String javaName) {
        this.bitLength = bitStrength;
        this.securityStrength = securityStrength;
        this.javaName = javaName;
    }

    public String getJavaName() {
        return javaName;
    }

    public int getBitLength() {
        return bitLength;
    }

    public int getSecurityStrength() {
        return securityStrength;
    }
}
