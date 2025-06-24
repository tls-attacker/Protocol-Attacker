/*
 * Protocol-Attacker - A Framework to create Protocol Analysis Tools
 *
 * Copyright 2023-2024 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.protocol.crypto.signature;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import de.rub.nds.modifiablevariable.biginteger.ModifiableBigInteger;
import de.rub.nds.modifiablevariable.util.Modifiable;
import java.math.BigInteger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class EddsaSignatureComputationsTest {

    private EddsaSignatureComputations computations;
    private BigInteger testBigInt = new BigInteger("12345678901234567890");

    @BeforeEach
    void setUp() {
        computations = new EddsaSignatureComputations();
    }

    @Test
    void testPrivateKeyGetterSetter() {
        // Initially null
        assertNull(computations.getPrivateKey());

        // Set and get with ModifiableBigInteger
        ModifiableBigInteger modifiableBigInt = Modifiable.explicit(testBigInt);
        computations.setPrivateKey(modifiableBigInt);
        assertEquals(modifiableBigInt, computations.getPrivateKey());
    }
}
