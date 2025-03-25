/*
 * Protocol-Attacker - A Framework to create Protocol Analysis Tools
 *
 * Copyright 2023-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.protocol.crypto.dsa;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.math.BigInteger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class DsaGroupTest {

    private ExplicitDsaParameters explicitParameters;

    @BeforeEach
    void setUp() {
        explicitParameters =
                new ExplicitDsaParameters(
                        new BigInteger("23"), // p
                        new BigInteger("11"), // q
                        new BigInteger("2")); // g
    }

    @Test
    void testDsaGroupParameters() {
        assertEquals(5, explicitParameters.getElementSizeBits());
    }

    @Test
    void testDsaGroupOperation() {
        DsaGroup group = (DsaGroup) explicitParameters.getGroup();
        BigInteger a = new BigInteger("3");
        BigInteger b = new BigInteger("5");
        BigInteger result = group.groupOperation(a, b);
        assertEquals(new BigInteger("15").mod(explicitParameters.getP()), result);
    }

    @Test
    void testDsaNTimesGroupOperation() {
        DsaGroup group = (DsaGroup) explicitParameters.getGroup();
        BigInteger a = new BigInteger("2");
        BigInteger scalar = new BigInteger("4");
        BigInteger result = group.nTimesGroupOperation(a, scalar);
        assertEquals(new BigInteger("16").mod(explicitParameters.getP()), result);
    }

    @Test
    void testDsaNTimesGroupOperationOnGenerator() {
        DsaGroup group = (DsaGroup) explicitParameters.getGroup();
        BigInteger scalar = new BigInteger("3");
        BigInteger result = group.nTimesGroupOperationOnGenerator(scalar);
        assertEquals(new BigInteger("8").mod(explicitParameters.getP()), result);
    }
}
