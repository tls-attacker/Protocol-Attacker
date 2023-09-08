/*
 * Protocol-Attacker - A framework to create protocol analysis tools
 *
 * Copyright 2023-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.protocol.constants;

public enum SignatureAlgorithm {
    RSA_PKCS1("RSA PKCS#1.5"),
    DSA("DSA (DSS)"),
    ECDSA("ECDSA"),
    RSA_PSS("RSA PSS"),
    ED25519("Ed25519"),
    ED448("Ed448"),
    GOSTR34102001("GOSTR34102001"),
    GOSTR34102012_256("GOSTR34102012 (256 bit)"),
    GOSTR34102012_512("GOSTR34102012 (512 bit)");

    private String humanReadable;

    private SignatureAlgorithm(String humanReadable) {
        this.humanReadable = humanReadable;
    }

    public String getHumanReadable() {
        return humanReadable;
    }
}
