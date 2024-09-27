/*
 * Protocol-Attacker - A Framework to create Protocol Analysis Tools
 *
 * Copyright 2023-2024 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.protocol.constants;

/** Metadata for hash algorithms. */
public enum MacAlgorithm {
    NONE(0, 0, null),
    /**
     * The MAC algorithm used in SLL3 and before. Its slightly different to HMAC
     */
    SSLMAC_MD5(16, 16, "SslMacMD5"), //TODO Move to TLS-Attacker
    /**
     * The MAC algorithm used in SLL3 and before. Its slightly different to HMAC
     */
    SSLMAC_SHA1(20, 20, "SslMacSHA1"), //TODO Move to TLS-Attacker
    HMAC_MD5(16, 16, "HmacMD5"),
    HMAC_SHA1(20, 20, "HmacSHA1"),
    HMAC_SHA256(32, 32, "HmacSHA256"),
    HMAC_SHA384(48, 48, "HmacSHA384"),
    HMAC_SHA512(64, 64, "HmacSHA512"),
    HMAC_SHA512_224(28, 28, "HmacSHA512/224"),
    HMAC_SHA512_256(32, 32, "HmacSHA512/256"),
    IMIT_GOST28147(4, 32, "GOST28147MAC"),
    HMAC_GOSTR3411(32, 32, "HmacGOST3411"),
    HMAC_GOSTR3411_2012_256(32, 32, "HmacGOST3411-2012-256"),
    HMAC_SM3(32, 32, "HmacSM3");

    /** The length of a MAC in byte */
    private int macLength;

    /** The lenght of a MAC in byte */
    private int keySize;

    private String javaName;

    private MacAlgorithm(int macLength, int keySize, String javaName) {
        this.macLength = macLength;
        this.keySize = keySize;
        this.javaName = javaName;
    }

    public String getJavaName() {
        return javaName;
    }

    public int getMacLength() {
        return macLength;
    }

    public int getKeySize() {
        return keySize;
    }
}
