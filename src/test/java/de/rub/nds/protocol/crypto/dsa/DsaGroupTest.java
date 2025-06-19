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
    private DsaGroup group;

    @BeforeEach
    void setUp() {
        explicitParameters =
                new ExplicitDsaParameters(
                        new BigInteger("23"), // p
                        new BigInteger("11"), // q
                        new BigInteger("2")); // g
        group = (DsaGroup) explicitParameters.getGroup();
    }

    @Test
    void testDsaGroupParameters() {
        assertEquals(5, explicitParameters.getElementSizeBits());
    }

    @Test
    void testDsaGroupOperation() {
        BigInteger a = new BigInteger("3");
        BigInteger b = new BigInteger("5");
        BigInteger result = group.groupOperation(a, b);
        assertEquals(new BigInteger("15").mod(explicitParameters.getP()), result);
    }

    @Test
    void testDsaGroupOperationWithZero() {
        BigInteger a = BigInteger.ZERO;
        BigInteger b = new BigInteger("5");
        BigInteger result = group.groupOperation(a, b);
        assertEquals(BigInteger.ZERO, result);
    }

    @Test
    void testDsaGroupOperationWithOne() {
        BigInteger a = BigInteger.ONE;
        BigInteger b = new BigInteger("5");
        BigInteger result = group.groupOperation(a, b);
        assertEquals(new BigInteger("5"), result);
    }

    @Test
    void testDsaGroupOperationWithP() {
        BigInteger a = explicitParameters.getP();
        BigInteger b = new BigInteger("5");
        BigInteger result = group.groupOperation(a, b);
        assertEquals(BigInteger.ZERO, result);
    }

    @Test
    void testDsaGroupOperationWithLargeValues() {
        BigInteger a = new BigInteger("999999999999999999999999999999");
        BigInteger b = new BigInteger("888888888888888888888888888888");
        BigInteger result = group.groupOperation(a, b);
        BigInteger expected = a.multiply(b).mod(explicitParameters.getP());
        assertEquals(expected, result);
    }

    @Test
    void testDsaNTimesGroupOperation() {
        BigInteger a = new BigInteger("2");
        BigInteger scalar = new BigInteger("4");
        BigInteger result = group.nTimesGroupOperation(a, scalar);
        assertEquals(new BigInteger("16").mod(explicitParameters.getP()), result);
    }

    @Test
    void testDsaNTimesGroupOperationWithZeroScalar() {
        BigInteger a = new BigInteger("5");
        BigInteger scalar = BigInteger.ZERO;
        BigInteger result = group.nTimesGroupOperation(a, scalar);
        assertEquals(BigInteger.ONE, result);
    }

    @Test
    void testDsaNTimesGroupOperationWithOneScalar() {
        BigInteger a = new BigInteger("5");
        BigInteger scalar = BigInteger.ONE;
        BigInteger result = group.nTimesGroupOperation(a, scalar);
        assertEquals(new BigInteger("5"), result);
    }

    @Test
    void testDsaNTimesGroupOperationWithNegativeScalar() {
        BigInteger a = new BigInteger("2");
        BigInteger scalar = new BigInteger("-3");
        BigInteger result = group.nTimesGroupOperation(a, scalar);
        BigInteger expected = a.modPow(scalar, explicitParameters.getP());
        assertEquals(expected, result);
    }

    @Test
    void testDsaNTimesGroupOperationWithLargeScalar() {
        BigInteger a = new BigInteger("2");
        BigInteger scalar = new BigInteger("999999999999999999999999999999");
        BigInteger result = group.nTimesGroupOperation(a, scalar);
        BigInteger expected = a.modPow(scalar, explicitParameters.getP());
        assertEquals(expected, result);
    }

    @Test
    void testDsaNTimesGroupOperationOnGenerator() {
        BigInteger scalar = new BigInteger("3");
        BigInteger result = group.nTimesGroupOperationOnGenerator(scalar);
        assertEquals(new BigInteger("8").mod(explicitParameters.getP()), result);
    }

    @Test
    void testDsaNTimesGroupOperationOnGeneratorWithZeroScalar() {
        BigInteger scalar = BigInteger.ZERO;
        BigInteger result = group.nTimesGroupOperationOnGenerator(scalar);
        assertEquals(BigInteger.ONE, result);
    }

    @Test
    void testDsaNTimesGroupOperationOnGeneratorWithOneScalar() {
        BigInteger scalar = BigInteger.ONE;
        BigInteger result = group.nTimesGroupOperationOnGenerator(scalar);
        assertEquals(explicitParameters.getG(), result);
    }

    @Test
    void testDsaNTimesGroupOperationOnGeneratorWithNegativeScalar() {
        BigInteger scalar = new BigInteger("-2");
        BigInteger result = group.nTimesGroupOperationOnGenerator(scalar);
        BigInteger expected = explicitParameters.getG().modPow(scalar, explicitParameters.getP());
        assertEquals(expected, result);
    }

    @Test
    void testGetP() {
        assertEquals(new BigInteger("23"), group.getP());
    }

    @Test
    void testGetQ() {
        assertEquals(new BigInteger("11"), group.getQ());
    }

    @Test
    void testGetParameters() {
        assertEquals(explicitParameters, group.getParameters());
    }

    @Test
    void testGetGenerator() {
        assertEquals(new BigInteger("2"), group.getGenerator());
    }

    @Test
    void testConstructorWithDifferentParameters() {
        ExplicitDsaParameters params =
                new ExplicitDsaParameters(
                        new BigInteger("47"), // p
                        new BigInteger("23"), // q
                        new BigInteger("5")); // g
        DsaGroup newGroup = new DsaGroup(params);
        assertEquals(params.getP(), newGroup.getP());
        assertEquals(params.getQ(), newGroup.getQ());
        assertEquals(params.getG(), newGroup.getGenerator());
    }
}
