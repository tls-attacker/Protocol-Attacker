/*
 * Protocol-Attacker - A Framework to create Protocol Analysis Tools
 *
 * Copyright 2023-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.protocol.crypto.ec;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.protocol.constants.EcCurveEquationType;
import de.rub.nds.protocol.constants.GroupParameters;
import de.rub.nds.protocol.constants.NamedEllipticCurveParameters;
import de.rub.nds.protocol.constants.PointFormat;
import de.rub.nds.protocol.crypto.CyclicGroup;
import de.rub.nds.protocol.exception.PreparationException;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class PointFormatter {

    private static final Logger LOGGER = LogManager.getLogger();

    public static byte[] formatToByteArray(
            GroupParameters<?> groupParameters, Point point, PointFormat format) {
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        if (point.isAtInfinity()) {
            return new byte[1];
        }
        int elementLength =
                ArrayConverter.bigIntegerToByteArray(point.getFieldX().getModulus()).length;
        if (groupParameters instanceof NamedEllipticCurveParameters
                && ((NamedEllipticCurveParameters) groupParameters).getEquationType()
                        == EcCurveEquationType.SHORT_WEIERSTRASS) {
            switch (format) {
                case UNCOMPRESSED:
                    stream.write(0x04);
                    try {
                        stream.write(
                                ArrayConverter.bigIntegerToNullPaddedByteArray(
                                        point.getFieldX().getData(), elementLength));
                        stream.write(
                                ArrayConverter.bigIntegerToNullPaddedByteArray(
                                        point.getFieldY().getData(), elementLength));
                    } catch (IOException ex) {
                        throw new PreparationException("Could not serialize ec point", ex);
                    }
                    return stream.toByteArray();
                case COMPRESSED:
                    CyclicGroup<?> group = groupParameters.getGroup();
                    if (!(group instanceof EllipticCurve)) {
                        throw new IllegalArgumentException(
                                "Cannot convert Point for non-elliptic curve");
                    }
                    EllipticCurve curve = (EllipticCurve) group;
                    if (curve.createAPointOnCurve(point.getFieldX().getData())
                            .getFieldY()
                            .getData()
                            .equals(point.getFieldY().getData())) {
                        stream.write(0x03);
                    } else {
                        stream.write(0x02);
                    }
                    try {
                        stream.write(
                                ArrayConverter.bigIntegerToNullPaddedByteArray(
                                        point.getFieldX().getData(), elementLength));
                    } catch (IOException ex) {
                        throw new PreparationException("Could not serialize ec point", ex);
                    }
                    return stream.toByteArray();
                default:
                    throw new UnsupportedOperationException("Unsupported PointFormat: " + format);
            }
        } else {
            try {
                byte[] coordinate =
                        ArrayConverter.bigIntegerToNullPaddedByteArray(
                                point.getFieldX().getData(), elementLength);
                stream.write(coordinate);
            } catch (IOException ex) {
                throw new PreparationException("Could not serialize ec point", ex);
            }
            return stream.toByteArray();
        }
    }

    public static byte[] toRawFormat(Point point) {
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        if (point.isAtInfinity()) {
            return new byte[1];
        }
        int elementLength =
                ArrayConverter.bigIntegerToByteArray(point.getFieldX().getModulus()).length;
        try {
            stream.write(
                    ArrayConverter.bigIntegerToNullPaddedByteArray(
                            point.getFieldX().getData(), elementLength));
            stream.write(
                    ArrayConverter.bigIntegerToNullPaddedByteArray(
                            point.getFieldY().getData(), elementLength));
        } catch (IOException ex) {
            throw new PreparationException("Could not serialize ec point", ex);
        }
        return stream.toByteArray();
    }

    /**
     * Tries to read the first N byte[] as a point of the curve of the form x|y. If the byte[] has
     * enough bytes the base point of the named group is returned
     *
     * @param groupParameters
     * @param pointBytes
     * @return
     */
    public static Point fromRawFormat(GroupParameters<?> groupParameters, byte[] pointBytes) {
        CyclicGroup<?> group = groupParameters.getGroup();
        if (!(group instanceof EllipticCurve)) {
            LOGGER.warn(
                    "Trying to convert bytes for a non elliptic curve to a Point. Returning null");
            return null;
        }
        Point basePoint = ((EllipticCurve) group).getBasePoint();
        int elementLength = groupParameters.getElementSizeBytes();
        if (pointBytes.length < elementLength * 2) {
            LOGGER.warn(
                    "Cannot decode byte[] to point of {}. Returning base point", groupParameters);
            return basePoint;
        }
        ByteArrayInputStream inputStream = new ByteArrayInputStream(pointBytes);
        byte[] coordX = new byte[elementLength];
        byte[] coordY = new byte[elementLength];
        try {
            inputStream.read(coordX);
            inputStream.read(coordY);
        } catch (IOException ex) {
            LOGGER.warn("Could not read from byteArrayStream. Returning base point", ex);
            return basePoint;
        }
        return ((EllipticCurve) group)
                .getPoint(new BigInteger(1, coordX), new BigInteger(1, coordY));
    }

    public static Point formatFromByteArray(
            GroupParameters<?> groupParameters, byte[] compressedPoint) {
        ByteArrayInputStream inputStream = new ByteArrayInputStream(compressedPoint);
        CyclicGroup<?> group = groupParameters.getGroup();
        if (!(group instanceof EllipticCurve)) {
            LOGGER.warn(
                    "Trying to convert bytes for a non elliptic curve to a Point. Returning null");

            return null;
        }
        EllipticCurve curve = (EllipticCurve) group;
        int elementLength = groupParameters.getElementSizeBytes();
        if (compressedPoint.length == 0) {
            LOGGER.warn("Could not parse point. Point is empty. Returning base point");
            return curve.getBasePoint();
        }
        if (groupParameters instanceof NamedEllipticCurveParameters
                && ((NamedEllipticCurveParameters) groupParameters).getEquationType()
                        == EcCurveEquationType.SHORT_WEIERSTRASS) {
            int pointFormat = inputStream.read();
            byte[] coordX = new byte[elementLength];
            switch (pointFormat) {
                case 2:
                case 3:
                    if (compressedPoint.length != elementLength + 1) {
                        LOGGER.warn(
                                "Could not parse point. Point needs to be "
                                        + (elementLength + 1)
                                        + " bytes long, but was "
                                        + compressedPoint.length
                                        + "bytes long. Returning base point");

                        return curve.getBasePoint();
                    }
                    try {
                        inputStream.read(coordX);
                    } catch (IOException ex) {
                        LOGGER.warn(
                                "Could not read from byteArrayStream. Returning base point", ex);
                        return curve.getBasePoint();
                    }
                    Point decompressedPoint = curve.createAPointOnCurve(new BigInteger(1, coordX));
                    if (pointFormat == 2) {
                        decompressedPoint = curve.inverseAffine(decompressedPoint);
                    }
                    return decompressedPoint;

                case 4:
                    if (compressedPoint.length != elementLength * 2 + 1) {
                        LOGGER.warn(
                                "Could not parse point. Point needs to be "
                                        + (elementLength * 2 + 1)
                                        + " bytes long, but was "
                                        + compressedPoint.length
                                        + "bytes long. Returning base point");
                        return curve.getBasePoint();
                    }

                    byte[] coordY = new byte[elementLength];
                    try {
                        inputStream.read(coordX);
                        inputStream.read(coordY);
                    } catch (IOException ex) {
                        LOGGER.warn(
                                "Could not read from byteArrayStream. Returning base point", ex);
                        return curve.getBasePoint();
                    }
                    return curve.getPoint(new BigInteger(1, coordX), new BigInteger(1, coordY));

                default:
                    throw new UnsupportedOperationException(
                            "Unsupported PointFormat: " + pointFormat);
            }
        } else {
            if (compressedPoint.length != elementLength) {
                LOGGER.warn(
                        "Could not parse point. Point needs to be "
                                + elementLength
                                + " bytes long, but was "
                                + compressedPoint.length
                                + "bytes long. Returning base point");
                return curve.getBasePoint();
            }
            byte[] coordX = new byte[elementLength];
            try {
                inputStream.read(coordX);
            } catch (IOException ex) {
                LOGGER.warn("Could not read from byteArrayStream. Returning base point", ex);
                return curve.getBasePoint();
            }
            RFC7748Curve rfc7748Curve = (RFC7748Curve) group;
            return curve.createAPointOnCurve(
                    rfc7748Curve.decodeCoordinate(new BigInteger(1, coordX)));
        }
    }

    public static PointFormat getPointFormat(byte[] encodedPointBytes) {
        if (encodedPointBytes.length == 0) {
            return PointFormat.UNCOMPRESSED;
        } else {
            return encodedPointBytes[0] == 0x04 ? PointFormat.UNCOMPRESSED : PointFormat.COMPRESSED;
        }
    }

    private PointFormatter() {}
}
