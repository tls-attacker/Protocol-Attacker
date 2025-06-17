/*
 * Protocol-Attacker - A Framework to create Protocol Analysis Tools
 *
 * Copyright 2023-2024 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.protocol.crypto.signature;

import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class SignatureComputationsSimpleTest {

    /** Test class for SignatureComputations. */
    private static class TestSignatureComputations extends SignatureComputations {
        // Just for testing
    }

    @Test
    void testSignatureValidGetterSetter() {
        SignatureComputations computations = new TestSignatureComputations();

        // Initially null
        assertNull(computations.getSignatureValid());

        // Test setter/getter
        computations.setSignatureValid(true);
        assertTrue(computations.getSignatureValid());
    }
}
