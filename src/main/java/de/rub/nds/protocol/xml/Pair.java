/*
 * Protocol-Attacker - A Framework to create Protocol Analysis Tools
 *
 * Copyright 2023-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.protocol.xml;

import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlRootElement;

/** Custom implementation of Pair to enable XML serialisation */
@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class Pair<L, R> {

    private L leftElement;
    private R rightElement;

    @SuppressWarnings("unused")
    private Pair() {}

    public Pair(L leftElement, R rightElement) {
        this.leftElement = leftElement;
        this.rightElement = rightElement;
    }

    public L getLeftElement() {
        return leftElement;
    }

    public void setLeftElement(L leftElement) {
        this.leftElement = leftElement;
    }

    public R getRightElement() {
        return rightElement;
    }

    public void setRightElement(R rightElement) {
        this.rightElement = rightElement;
    }

    public L getKey() {
        return leftElement;
    }

    public R getValue() {
        return rightElement;
    }
}
