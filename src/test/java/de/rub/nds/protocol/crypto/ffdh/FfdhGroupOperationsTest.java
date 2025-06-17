/*
 * Protocol-Attacker - A Framework to create Protocol Analysis Tools
 *
 * Copyright 2023-2024 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.protocol.crypto.ffdh;

import static org.junit.jupiter.api.Assertions.assertEquals;

import de.rub.nds.protocol.constants.FfdhGroupParameters;
import java.math.BigInteger;
import org.junit.jupiter.api.Test;

public class FfdhGroupOperationsTest {

    @Test
    public void testFFDHGroupOperations() {
        // Create a simple FfdhGroup for testing
        BigInteger modulus = new BigInteger("23"); // Small prime for testing
        BigInteger generator = new BigInteger("2");
        FfdhGroupParameters params = new ExplicitFfdhGroupParameters(generator, modulus);
        FfdhGroup group = new FfdhGroup(params);

        // Test getParameters
        assertEquals(params, group.getParameters());

        // Test getModulus
        assertEquals(modulus, group.getModulus());

        // Test getGenerator
        assertEquals(generator, group.getGenerator());

        // Test groupOperation (multiplication)
        BigInteger a = new BigInteger("5");
        BigInteger b = new BigInteger("7");
        assertEquals(a.multiply(b), group.groupOperation(a, b));

        // Test nTimesGroupOperation (modular exponentiation)
        BigInteger scalar = new BigInteger("3");
        assertEquals(a.modPow(scalar, modulus), group.nTimesGroupOperation(a, scalar));

        // Test nTimesGroupOperationOnGenerator
        assertEquals(
                generator.modPow(scalar, modulus), group.nTimesGroupOperationOnGenerator(scalar));
    }
}
