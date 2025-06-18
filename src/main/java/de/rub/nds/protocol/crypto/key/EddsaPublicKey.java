/*
 * Protocol-Attacker - A Framework to create Protocol Analysis Tools
 *
 * Copyright 2023-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.protocol.crypto.key;

import de.rub.nds.protocol.constants.AsymmetricAlgorithmType;
import de.rub.nds.protocol.constants.NamedEllipticCurveParameters;
import de.rub.nds.protocol.crypto.ec.Point;

/** Stores an EdDSA public key consisting of a point on an Edwards curve. */
public class EddsaPublicKey implements PublicKeyContainer {

    private Point publicPoint;

    private NamedEllipticCurveParameters parameters;

    /** Default constructor for deserialization. */
    @SuppressWarnings("unused")
    private EddsaPublicKey() {
        this.publicPoint = null;
        this.parameters = null;
    }

    /**
     * Constructs an EdDSA public key with the specified public point and curve parameters.
     *
     * @param publicPoint the public key point on the elliptic curve
     * @param parameters the elliptic curve parameters
     */
    public EddsaPublicKey(Point publicPoint, NamedEllipticCurveParameters parameters) {
        this.publicPoint = publicPoint;
        this.parameters = parameters;
    }

    /**
     * Gets the public key point on the elliptic curve.
     *
     * @return the public key point
     */
    public Point getPublicPoint() {
        return publicPoint;
    }

    /**
     * Sets the public key point on the elliptic curve.
     *
     * @param publicPoint the public key point to set
     */
    public void setPublicPoint(Point publicPoint) {
        this.publicPoint = publicPoint;
    }

    /**
     * Gets the elliptic curve parameters associated with this public key.
     *
     * @return the elliptic curve parameters
     */
    public NamedEllipticCurveParameters getParameters() {
        return parameters;
    }

    /**
     * Sets the elliptic curve parameters for this public key.
     *
     * @param parameters the elliptic curve parameters to set
     */
    public void setParameters(NamedEllipticCurveParameters parameters) {
        this.parameters = parameters;
    }

    /**
     * Returns the element size in bits for the elliptic curve parameters.
     *
     * @return the element size in bits
     */
    @Override
    public int length() {
        return parameters.getElementSizeBits();
    }

    /**
     * Returns a hash code value for this EdDSA public key.
     *
     * @return a hash code value for this object
     */
    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((publicPoint == null) ? 0 : publicPoint.hashCode());
        result = prime * result + ((parameters == null) ? 0 : parameters.hashCode());
        return result;
    }

    /**
     * Indicates whether some other object is "equal to" this EdDSA public key.
     *
     * @param obj the reference object with which to compare
     * @return true if this object is the same as the obj argument; false otherwise
     */
    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (obj == null) return false;
        if (getClass() != obj.getClass()) return false;
        EddsaPublicKey other = (EddsaPublicKey) obj;
        if (publicPoint == null) {
            if (other.publicPoint != null) return false;
        } else if (!publicPoint.equals(other.publicPoint)) return false;
        if (parameters != other.parameters) return false;
        return true;
    }

    /**
     * Returns the asymmetric algorithm type for this key.
     *
     * @return AsymmetricAlgorithmType.EDDSA
     */
    @Override
    public AsymmetricAlgorithmType getAlgorithmType() {
        return AsymmetricAlgorithmType.EDDSA;
    }
}
