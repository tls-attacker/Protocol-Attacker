/*
 * Protocol-Attacker - A Framework to create Protocol Analysis Tools
 *
 * Copyright 2023-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.protocol.constants;

import de.rub.nds.protocol.crypto.CyclicGroup;

/**
 * Interface for cryptographic group parameters.
 * Defines methods for accessing properties of mathematical groups used in cryptography.
 *
 * @param <GroupElementT> the type of elements in the group
 */
public interface GroupParameters<GroupElementT> {

    /**
     * Returns the size of and element in the group in bits.
     *
     * @return The size of an element in the group in bits.
     */
    int getElementSizeBits();

    /**
     * Returns the size of and element in the group in bytes. If an element would be 13 bits, then
     * this method would return 2.
     *
     * @return The size of an element in the group in bytes.
     */
    int getElementSizeBytes();

    /**
     * Returns an instance of the mathematical group that is described by these parameters.
     *
     * @return An instance of the underlying group
     */
    CyclicGroup<GroupElementT> getGroup();
}
