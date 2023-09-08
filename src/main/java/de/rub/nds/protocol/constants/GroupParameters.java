/*
 * Protocol-Attacker - A Framework to create Protocol Analysis Tools
 *
 * Copyright 2023-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.protocol.constants;

public interface GroupParameters {

    /**
     * Returns the size of and element in the group in bits.
     *
     * @return The size of an element in the group in bits.
     */
    public abstract int getElementSize();
}
