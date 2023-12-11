/*
 * Protocol-Attacker - A Framework to create Protocol Analysis Tools
 *
 * Copyright 2023-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.protocol.crypto;

import java.math.BigInteger;

public interface CyclicGroup<GroupElementT> {
    /**
     * Peforms the group operation on the two given elements.
     *
     * @param a First group element
     * @param b Second group element
     * @return The result of c = a o b
     */
    public GroupElementT groupOperation(GroupElementT a, GroupElementT b);

    /**
     * Performs the group operation on the element a with itself scalar times.
     *
     * @param a The group element
     * @param scalar How often the group operation should be applied
     * @return The result of c = a o a o ... o a
     */
    public GroupElementT nTimesGroupOperation(GroupElementT a, BigInteger scalar);

    /**
     * Performs the group operation on the generator a with itself scalar times.
     *
     * @param scalar How often the group operation should be applied
     * @return The result of c = g o g o ... o g
     */
    public GroupElementT nTimesGroupOperationOnGenerator(BigInteger scalar);

    /**
     * Returns the group generator.
     *
     * @return The group generator
     */
    public GroupElementT getGenerator();
}
