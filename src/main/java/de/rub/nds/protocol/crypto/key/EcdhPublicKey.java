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
import java.math.BigInteger;

public class EcdhPublicKey implements PublicKeyContainer {

    private Point publicPoint;

    private NamedEllipticCurveParameters parameters;

    public EcdhPublicKey(Point publicPoint, NamedEllipticCurveParameters parameters) {
        this.publicPoint = publicPoint;
        this.parameters = parameters;
    }

    public EcdhPublicKey(
            BigInteger publicPointX,
            BigInteger publicPointY,
            NamedEllipticCurveParameters parameters) {
        this.publicPoint = parameters.getGroup().getPoint(publicPointX, publicPointY);
        this.parameters = parameters;
    }

    public Point getPublicPoint() {
        return publicPoint;
    }

    public void setPublicPoint(Point publicPoint) {
        this.publicPoint = publicPoint;
    }

    public NamedEllipticCurveParameters getParameters() {
        return parameters;
    }

    public void setParameters(NamedEllipticCurveParameters parameters) {
        this.parameters = parameters;
    }

    @Override
    public int length() {
        return parameters.getElementSizeBits();
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((publicPoint == null) ? 0 : publicPoint.hashCode());
        result = prime * result + ((parameters == null) ? 0 : parameters.hashCode());
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (obj == null) return false;
        if (getClass() != obj.getClass()) return false;
        EcdhPublicKey other = (EcdhPublicKey) obj;
        if (publicPoint == null) {
            if (other.publicPoint != null) return false;
        } else if (!publicPoint.equals(other.publicPoint)) return false;
        if (parameters != other.parameters) return false;
        return true;
    }

    @Override
    public AsymmetricAlgorithmType getAlgorithmType() {
        return AsymmetricAlgorithmType.ECDH;
    }
}
