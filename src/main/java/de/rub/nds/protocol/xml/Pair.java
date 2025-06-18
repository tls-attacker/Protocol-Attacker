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

/**
 * XML-serializable generic pair container for storing two related objects. Provides both
 * element-based (left/right) and key-value access patterns.
 *
 * @param <L> the type of the left element (key)
 * @param <R> the type of the right element (value)
 */
@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class Pair<L, R> {

    private L leftElement;
    private R rightElement;

    /** Default constructor for deserialization. */
    @SuppressWarnings("unused")
    private Pair() {}

    /**
     * Constructs a new Pair with the specified left and right elements.
     *
     * @param leftElement the left element of the pair
     * @param rightElement the right element of the pair
     */
    public Pair(L leftElement, R rightElement) {
        this.leftElement = leftElement;
        this.rightElement = rightElement;
    }

    /**
     * Returns the left element of this pair.
     *
     * @return the left element
     */
    public L getLeftElement() {
        return leftElement;
    }

    /**
     * Sets the left element of this pair.
     *
     * @param leftElement the new left element
     */
    public void setLeftElement(L leftElement) {
        this.leftElement = leftElement;
    }

    /**
     * Returns the right element of this pair.
     *
     * @return the right element
     */
    public R getRightElement() {
        return rightElement;
    }

    /**
     * Sets the right element of this pair.
     *
     * @param rightElement the new right element
     */
    public void setRightElement(R rightElement) {
        this.rightElement = rightElement;
    }

    /**
     * Returns the key (left element) of this pair. This method provides an alternative name for
     * accessing the left element.
     *
     * @return the left element as key
     */
    public L getKey() {
        return leftElement;
    }

    /**
     * Returns the value (right element) of this pair. This method provides an alternative name for
     * accessing the right element.
     *
     * @return the right element as value
     */
    public R getValue() {
        return rightElement;
    }
}
