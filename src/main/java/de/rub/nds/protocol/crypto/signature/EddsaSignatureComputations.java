/*
 * Protocol-Attacker - A Framework to create Protocol Analysis Tools
 *
 * Copyright 2023-2024 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.protocol.crypto.signature;

import de.rub.nds.modifiablevariable.biginteger.ModifiableBigInteger;

public class EddsaSignatureComputations extends SignatureComputations {

    private ModifiableBigInteger privateKey;

    public ModifiableBigInteger getPrivateKey() {
        return privateKey;
    }

    public void setPrivateKey(ModifiableBigInteger privateKey) {
        this.privateKey = privateKey;
    }
}
