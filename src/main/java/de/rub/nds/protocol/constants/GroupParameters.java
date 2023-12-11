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

public interface GroupParameters<GroupElementT> {

    /**
     * Returns the size of and element in the group in bits.
     *
     * @return The size of an element in the group in bits.
     */
    public abstract int getElementSizeBits();

    /**
     * Returns the size of and element in the group in bytes. If an element would be 13 bits, then
     * this method would return 2.
     *
     * @return The size of an element in the group in bytes.
     */
    public abstract int getElementSizeBytes();

    /**
     * Returns an instance of the mathematical group that is described by these parameters.
     *
     * @return An instasnce of the unterlying group
     */
    public CyclicGroup<GroupElementT> getGroup();
}
