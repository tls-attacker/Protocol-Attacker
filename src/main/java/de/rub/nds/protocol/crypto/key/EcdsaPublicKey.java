package de.rub.nds.protocol.crypto.key;

import de.rub.nds.protocol.constants.NamedEllipticCurveParameters;
import de.rub.nds.protocol.crypto.ec.Point;

public class EcdsaPublicKey implements PublicKeyContainer {

    private Point publicPoint;

    private NamedEllipticCurveParameters parameters;

    public EcdsaPublicKey(Point publicPoint, NamedEllipticCurveParameters parameters) {
        this.publicPoint = publicPoint;
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

}
