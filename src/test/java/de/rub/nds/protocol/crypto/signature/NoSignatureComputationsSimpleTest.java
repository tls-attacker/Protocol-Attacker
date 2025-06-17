/*
 * Protocol-Attacker - A Framework to create Protocol Analysis Tools
 *
 * Copyright 2023-2024 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.protocol.crypto.signature;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class NoSignatureComputationsSimpleTest {

    @Test
    void testConstructor() {
        // Verify that NoSignatureComputations can be instantiated
        NoSignatureComputations computations = new NoSignatureComputations();
        assertNotNull(computations);

        // Verify it inherits from SignatureComputations
        assertTrue(computations instanceof SignatureComputations);

        // Test initial state
        assertNull(computations.getSignatureBytes());
        assertNull(computations.getToBeSignedBytes());
        assertNull(computations.getDigestBytes());
        assertNull(computations.getSignatureValid());
    }
}
