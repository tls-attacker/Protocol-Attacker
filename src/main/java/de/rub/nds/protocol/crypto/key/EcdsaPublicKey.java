/*
 * Protocol-Attacker - A framework to create protocol analysis tools
 *
 * Copyright 2023-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
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
