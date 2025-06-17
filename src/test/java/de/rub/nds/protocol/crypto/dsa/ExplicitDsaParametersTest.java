/*
 * Protocol-Attacker - A Framework to create Protocol Analysis Tools
 *
 * Copyright 2023-2024 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.protocol.crypto.dsa;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.rub.nds.protocol.crypto.CyclicGroup;
import java.math.BigInteger;
import org.junit.jupiter.api.Test;

class ExplicitDsaParametersTest {

    @Test
    void testExplicitDsaParametersConstructor() {
        // Create explicit DSA parameters
        BigInteger p = new BigInteger("23");
        BigInteger q = new BigInteger("11");
        BigInteger g = new BigInteger("2");

        ExplicitDsaParameters parameters = new ExplicitDsaParameters(p, q, g);

        // Verify parameter values
        assertEquals(p, parameters.getP());
        assertEquals(q, parameters.getQ());
        assertEquals(g, parameters.getG());
        assertEquals(5, parameters.getElementSizeBits()); // log2(23) ≈ 4.52 -> 5 bits
    }

    @Test
    void testGetGroup() {
        // Create parameters
        BigInteger p = new BigInteger("23");
        BigInteger q = new BigInteger("11");
        BigInteger g = new BigInteger("2");

        ExplicitDsaParameters parameters = new ExplicitDsaParameters(p, q, g);

        // Get the group
        CyclicGroup<?> group = parameters.getGroup();

        // Verify group properties
        assertNotNull(group);
        assertTrue(group instanceof DsaGroup);
        assertEquals(g, group.getGenerator());

        // Test group operations
        BigInteger a = new BigInteger("3");
        BigInteger b = new BigInteger("5");
        BigInteger result = ((DsaGroup) group).groupOperation(a, b);
        assertEquals(new BigInteger("15").mod(p), result);
    }
}
