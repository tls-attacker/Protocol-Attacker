/*
 * Protocol-Attacker - A Framework to create Protocol Analysis Tools
 *
 * Copyright 2023-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.protocol.crypto.ec;

import de.rub.nds.protocol.constants.GroupParameters;
import de.rub.nds.protocol.crypto.CyclicGroup;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlElement;
import jakarta.xml.bind.annotation.XmlElements;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.Serializable;
import java.math.BigInteger;
import java.util.Objects;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Represents a point on an elliptic curve.
 *
 * <p>Points are stored in affine coordinates (x, y) or as the special point at infinity. The point
 * at infinity serves as the identity element for the group operation.
 */
@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class Point implements Serializable {

    private static final Logger LOGGER = LogManager.getLogger();

    /**
     * Creates a point on the elliptic curve defined by the given curve parameters.
     *
     * @param x The x-coordinate of the point
     * @param y The y-coordinate of the point
     * @param curveParameters The curve parameters defining the elliptic curve
     * @return A point on the curve, or null if the parameters do not define an elliptic curve
     */
    public static Point createPoint(
            BigInteger x, BigInteger y, GroupParameters<?> curveParameters) {
        CyclicGroup<?> group = curveParameters.getGroup();
        EllipticCurve curve;
        if (group instanceof EllipticCurve) {
            curve = (EllipticCurve) group;
        } else {
            LOGGER.warn("Cannot create point for non-elliptic curve");
            return null;
        }
        return curve.getPoint(x, y);
    }

    /*
     * Point objects are immutable. This should make deep copies in the methods of the EllipticCurve class unnecessary.
     */
    @XmlElements(
            value = {
                @XmlElement(type = FieldElementF2m.class, name = "xFieldElementF2m"),
                @XmlElement(type = FieldElementFp.class, name = "xFieldElementFp")
            })
    private final FieldElement fieldX;

    @XmlElements(
            value = {
                @XmlElement(type = FieldElementF2m.class, name = "yFieldElementF2m"),
                @XmlElement(type = FieldElementFp.class, name = "yFieldElementFp")
            })
    private final FieldElement fieldY;

    private final boolean infinity;

    /** Instantiates the point at infinity. */
    public Point() {
        this.infinity = true;
        this.fieldX = null;
        this.fieldY = null;
    }

    /**
     * Creates an affine point with the given field element coordinates.
     *
     * @param x x-coordinate as a field element
     * @param y y-coordinate as a field element
     */
    public Point(FieldElement x, FieldElement y) {
        this.fieldX = x;
        this.fieldY = y;
        this.infinity = false;
    }

    /**
     * Returns true if the point is the point at infinity. Returns false if the point is an affine
     * point.
     *
     * @return true if this is the point at infinity, false otherwise
     */
    public boolean isAtInfinity() {
        return this.infinity;
    }

    /**
     * Returns the x-coordinate of this point as a field element.
     *
     * @return The x-coordinate field element, or null if this is the point at infinity
     */
    public FieldElement getFieldX() {
        return this.fieldX;
    }

    /**
     * Returns the y-coordinate of this point as a field element.
     *
     * @return The y-coordinate field element, or null if this is the point at infinity
     */
    public FieldElement getFieldY() {
        return this.fieldY;
    }

    /** {@inheritDoc} */
    @Override
    public int hashCode() {
        int hash = 7;
        hash = 89 * hash + Objects.hashCode(this.fieldX);
        hash = 89 * hash + Objects.hashCode(this.fieldY);
        hash = 89 * hash + (this.infinity ? 1 : 0);
        return hash;
    }

    /** {@inheritDoc} */
    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final Point other = (Point) obj;
        if (this.infinity != other.infinity) {
            return false;
        }
        if (!Objects.equals(this.fieldX, other.fieldX)) {
            return false;
        }
        if (!Objects.equals(this.fieldY, other.fieldY)) {
            return false;
        }
        return true;
    }

    /** {@inheritDoc} */
    @Override
    public String toString() {
        if (this.isAtInfinity()) {
            return "Point: Infinity";
        } else {
            return "Point: ("
                    + this.getFieldX().toString()
                    + ", "
                    + this.getFieldY().toString()
                    + ")";
        }
    }
}
