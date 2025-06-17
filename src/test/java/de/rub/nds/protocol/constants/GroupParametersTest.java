/*
 * Protocol-Attacker - A Framework to create Protocol Analysis Tools
 *
 * Copyright 2023-2024 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.protocol.constants;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import de.rub.nds.protocol.crypto.CyclicGroup;
import de.rub.nds.protocol.crypto.ffdh.FfdhGroup;
import de.rub.nds.protocol.crypto.ffdh.Rfc7919Group2048;
import java.math.BigInteger;
import org.junit.jupiter.api.Test;

public class GroupParametersTest {

    @Test
    public void testFfdhGroupParameters() {
        // Test using Rfc7919Group2048 as a concrete implementation of GroupParameters
        FfdhGroupParameters params = new Rfc7919Group2048();

        // Test getElementSizeBits()
        assertEquals(2048, params.getElementSizeBits());

        // Test getElementSizeBytes()
        assertEquals(256, params.getElementSizeBytes());

        // Test getGroup()
        CyclicGroup<BigInteger> group = params.getGroup();
        assertNotNull(group);
        assertEquals(FfdhGroup.class, group.getClass());
        assertEquals(BigInteger.TWO, group.getGenerator());
    }
}
