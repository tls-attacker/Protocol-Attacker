/*
 * Protocol-Attacker - A Framework to create Protocol Analysis Tools
 *
 * Copyright 2023-2024 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.protocol.crypto;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import de.rub.nds.protocol.crypto.dsa.ExplicitDsaParameters;
import de.rub.nds.protocol.crypto.ffdh.FfdhGroup;
import de.rub.nds.protocol.crypto.ffdh.Rfc7919Group2048;
import java.math.BigInteger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class CyclicGroupTest {

    private CyclicGroup<BigInteger> dsaGroup;
    private CyclicGroup<BigInteger> ffdhGroup;

    @BeforeEach
    void setUp() {
        // Create a DSA group for testing
        ExplicitDsaParameters dsaParameters =
                new ExplicitDsaParameters(
                        new BigInteger("23"), // p
                        new BigInteger("11"), // q
                        new BigInteger("2")); // g
        dsaGroup = dsaParameters.getGroup();

        // Create a FFDH group for testing
        ffdhGroup = new Rfc7919Group2048().getGroup();
    }

    @Test
    void testGroupOperation() {
        BigInteger a = new BigInteger("3");
        BigInteger b = new BigInteger("5");

        // Test DSA group operation (multiplication modulo p)
        BigInteger dsaResult = dsaGroup.groupOperation(a, b);
        assertEquals(new BigInteger("15").mod(new BigInteger("23")), dsaResult);

        // Test FFDH group operation (multiplication modulo p)
        BigInteger ffdhResult = ffdhGroup.groupOperation(a, b);
        assertEquals(a.multiply(b).mod(((FfdhGroup) ffdhGroup).getModulus()), ffdhResult);
    }

    @Test
    void testNTimesGroupOperation() {
        BigInteger element = new BigInteger("2");
        BigInteger scalar = new BigInteger("4");

        // Test DSA n-times group operation (element^scalar mod p)
        BigInteger dsaResult = dsaGroup.nTimesGroupOperation(element, scalar);
        assertEquals(new BigInteger("16").mod(new BigInteger("23")), dsaResult);

        // Test FFDH n-times group operation
        BigInteger ffdhResult = ffdhGroup.nTimesGroupOperation(element, scalar);
        assertEquals(element.modPow(scalar, ((FfdhGroup) ffdhGroup).getModulus()), ffdhResult);
    }

    @Test
    void testNTimesGroupOperationOnGenerator() {
        BigInteger scalar = new BigInteger("3");

        // Test DSA generator exponentiation (g^scalar mod p)
        BigInteger dsaResult = dsaGroup.nTimesGroupOperationOnGenerator(scalar);
        assertEquals(new BigInteger("8").mod(new BigInteger("23")), dsaResult);

        // Test FFDH generator exponentiation
        BigInteger ffdhResult = ffdhGroup.nTimesGroupOperationOnGenerator(scalar);
        assertEquals(
                ffdhGroup.getGenerator().modPow(scalar, ((FfdhGroup) ffdhGroup).getModulus()),
                ffdhResult);
    }

    @Test
    void testGetGenerator() {
        // Test DSA generator
        BigInteger dsaGenerator = dsaGroup.getGenerator();
        assertNotNull(dsaGenerator);
        assertEquals(new BigInteger("2"), dsaGenerator);

        // Test FFDH generator
        BigInteger ffdhGenerator = ffdhGroup.getGenerator();
        assertNotNull(ffdhGenerator);
        assertEquals(BigInteger.valueOf(2), ffdhGenerator);
    }
}
