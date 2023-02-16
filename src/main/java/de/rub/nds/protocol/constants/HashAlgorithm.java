/*
 * Protocol-Attacker - A framework to create protocol analysis tools
 *
 * Copyright 2023-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.protocol.constants;

public enum HashAlgorithm {
    NONE(""),
    MD2("1.2.840.113549.2.2"),
    MD5("1.2.840.113549.2.5"),
    SHA1("1.3.14.3.2.26"),
    SHA256("2.16.840.1.101.3.4.2.1"),
    SHA384("2.16.840.1.101.3.4.2.2"),
    SHA512("2.16.840.1.101.3.4.2.3");

    private String hashAlgorithmIdentifierOid;

    private HashAlgorithm(String hashAlgorithmIdentifierOid) {
        this.hashAlgorithmIdentifierOid = hashAlgorithmIdentifierOid;
    }

    public String getHashAlgorithmIdentifierOid() {
        return hashAlgorithmIdentifierOid;
    }
}
