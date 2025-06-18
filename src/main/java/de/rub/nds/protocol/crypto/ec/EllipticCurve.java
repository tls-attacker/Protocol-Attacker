/*
 * Protocol-Attacker - A Framework to create Protocol Analysis Tools
 *
 * Copyright 2023-2024 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.protocol.crypto.ec;

import de.rub.nds.protocol.crypto.CyclicGroup;
import java.math.BigInteger;

/**
 * Abstract base class for elliptic curves over finite fields.
 *
 * <p>This class provides the fundamental operations for elliptic curve cryptography, including
 * point arithmetic, scalar multiplication, and field operations. Supports both prime field (Fp) and
 * binary field (F2m) curves through subclasses.
 *
 * <p>Implements the CyclicGroup interface to provide group operations on curve points.
 */
public abstract class EllipticCurve implements CyclicGroup<Point> {

    private Point basePoint;
    private BigInteger basePointOrder;

    /** The modulus of the field over which the curve is defined. */
    private final BigInteger modulus;

    /**
     * Every child class must define its own public constructor. These constructors must be able to
     * set the coefficients for the curve. They can use this constructor to set the value of
     * modulus.
     *
     * @param modulus The modulus of the field over which the curve is defined.
     */
    protected EllipticCurve(BigInteger modulus) {
        this.modulus = modulus;
    }

    /**
     * Every child class must define its own public constructor. These constructors must be able to
     * set the coefficients for the curve. They can use this constructor to set the values of
     * modulus, basePoint and basePointOrder.
     *
     * @param modulus The modulus of the field over which the curve is defined.
     * @param basePointX The x coordinate of the base point.
     * @param basePointY The y coordinate of the base point.
     * @param basePointOrder The order of the base point.
     */
    protected EllipticCurve(
            BigInteger modulus,
            BigInteger basePointX,
            BigInteger basePointY,
            BigInteger basePointOrder) {
        this.modulus = modulus;
        this.basePoint = this.getPoint(basePointX, basePointY);
        this.basePointOrder = basePointOrder;
    }

    /**
     * Returns the result of p + q on this curve. If one point is null, the result will be null. If
     * one point is not on the curve and the calculations would require dividing by 0, the result
     * will be the point at infinity.
     *
     * @param p A point whose coordinates are elements of the field over which the curve is defined
     *     or the point at infinity.
     * @param q A point whose coordinates are elements of the field over which the curve is defined
     *     or the point at infinity.
     * @return The sum of the two points on the elliptic curve.
     */
    public Point add(Point p, Point q) {
        if (p.isAtInfinity()) {
            // O + q == q
            return q;
        }

        if (q.isAtInfinity()) {
            // p + O == p
            return p;
        }

        if (this.inverse(p).equals(q)) {
            // p == -q <=> -p == q
            // => p + q = O
            return new Point();
        }

        return this.additionFormular(p, q);
    }

    /**
     * Returns k*p on this curve. If the point is not on the curve and the calculations would
     * require dividing by 0, the result will be the point at infinity.
     *
     * @param k The scalar to multiply the point by.
     * @param p A point whose coordinates are elements of the field over which the curve is defined
     *     or the point at infinity.
     * @return The result of scalar multiplication k*p.
     */
    public Point mult(BigInteger k, Point p) {
        if (k.compareTo(BigInteger.ZERO) < 0) {
            k = k.negate();
            p = this.inverse(p);
        }

        // Double-and-add
        Point q = getPoint(BigInteger.ZERO, BigInteger.ZERO); // q == O

        for (int i = k.bitLength(); i > 0; i--) {

            q = this.add(q, q);

            if (k.testBit(i - 1)) {
                q = this.add(q, p);
            }
        }

        return q;
    }

    /**
     * Returns the unique point q with the property p + q = O on this curve. If p is null the result
     * will be null.
     *
     * @param p A point whose coordinates are elements of the field over which the curve is defined
     *     or the point at infinity.
     * @return The inverse of the given point.
     */
    public Point inverse(Point p) {
        if (p.isAtInfinity()) {
            // -O == O
            return p;
        } else {
            return this.inverseAffine(p);
        }
    }

    /**
     * Returns an affine point with coordinates x and y. The point's coordinates are elements of the
     * field over which this curve is defined. Whenever possible, this method should be used instead
     * of creating a point via its own constructor.
     *
     * @param x The x coordinate of the point.
     * @param y The y coordinate of the point.
     * @return A point on the elliptic curve with the given coordinates.
     */
    public abstract Point getPoint(BigInteger x, BigInteger y);

    /**
     * Returns true iff the point p is on the curve.
     *
     * @param p An affine point whose coordinates are elements of the field over which the curve is
     *     defined or the point at infinity.
     * @return true if the point is on the curve, false otherwise.
     */
    public abstract boolean isOnCurve(Point p);

    /**
     * Returns the unique (affine) point q with the property p + q = O on this curve.
     *
     * @param p An affine point whose coordinates are elements of the field over which the curve is
     *     defined.
     */
    protected abstract Point inverseAffine(Point p);

    /**
     * Returns p+q for two affine points p and q, with p != -q. If one point is not on the curve and
     * the calculations would require dividing by 0, the result will be the point at infinity.
     *
     * @param p An affine point whose coordinates are elements of the field over which the curve is
     *     defined.
     * @param q An affine point whose coordinates are elements of the field over which the curve is
     *     defined. Must not be equal to -p.
     */
    protected abstract Point additionFormular(Point p, Point q);

    /**
     * Returns the base point of this elliptic curve.
     *
     * @return The base point
     */
    public Point getBasePoint() {
        return this.basePoint;
    }

    /**
     * Returns the order of the base point.
     *
     * @return The base point order
     */
    public BigInteger getBasePointOrder() {
        return this.basePointOrder;
    }

    /**
     * Returns the modulus of the field over which the curve is defined.
     *
     * @return The field modulus
     */
    public BigInteger getModulus() {
        return this.modulus;
    }

    /**
     * Creates a point on the curve with the given x-coordinate.
     *
     * @param x The x-coordinate
     * @return A point on the curve with the given x-coordinate
     */
    public Point createAPointOnCurve(BigInteger x) {
        return createAPointOnCurve(x, true);
    }

    /**
     * Creates a point on the curve with the given x-coordinate.
     *
     * @param x The x-coordinate
     * @param returnBasepointUponError If true, returns the base point when no valid point can be
     *     found
     * @return A point on the curve with the given x-coordinate
     */
    public abstract Point createAPointOnCurve(BigInteger x, boolean returnBasepointUponError);

    /**
     * Creates a field element with the given value.
     *
     * @param value The value of the field element
     * @return A field element with the given value
     */
    public abstract FieldElement createFieldElement(BigInteger value);

    @Override
    public Point groupOperation(Point a, Point b) {
        return add(a, b);
    }

    @Override
    public Point nTimesGroupOperation(Point a, BigInteger scalar) {
        return mult(scalar, a);
    }

    @Override
    public Point getGenerator() {
        return getBasePoint();
    }

    @Override
    public Point nTimesGroupOperationOnGenerator(BigInteger scalar) {
        return nTimesGroupOperation(basePoint, scalar);
    }
}
