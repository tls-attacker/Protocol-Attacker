package de.rub.nds.protocol.constants;

import de.rub.nds.protocol.crypto.ec.EllipticCurve;
import de.rub.nds.protocol.crypto.ec.EllipticCurveBrainpoolP256R1;
import de.rub.nds.protocol.crypto.ec.EllipticCurveBrainpoolP384R1;
import de.rub.nds.protocol.crypto.ec.EllipticCurveBrainpoolP512R1;
import de.rub.nds.protocol.crypto.ec.EllipticCurveSECP160K1;
import de.rub.nds.protocol.crypto.ec.EllipticCurveSECP160R1;
import de.rub.nds.protocol.crypto.ec.EllipticCurveSECP160R2;
import de.rub.nds.protocol.crypto.ec.EllipticCurveSECP192K1;
import de.rub.nds.protocol.crypto.ec.EllipticCurveSECP192R1;
import de.rub.nds.protocol.crypto.ec.EllipticCurveSECP224K1;
import de.rub.nds.protocol.crypto.ec.EllipticCurveSECP224R1;
import de.rub.nds.protocol.crypto.ec.EllipticCurveSECP256K1;
import de.rub.nds.protocol.crypto.ec.EllipticCurveSECP256R1;
import de.rub.nds.protocol.crypto.ec.EllipticCurveSECP384R1;
import de.rub.nds.protocol.crypto.ec.EllipticCurveSECP521R1;
import de.rub.nds.protocol.crypto.ec.EllipticCurve25519;
import de.rub.nds.protocol.crypto.ec.EllipticCurveBrainpoolP160R1;
import de.rub.nds.protocol.crypto.ec.EllipticCurveBrainpoolP160T1;
import de.rub.nds.protocol.crypto.ec.EllipticCurveBrainpoolP192R1;
import de.rub.nds.protocol.crypto.ec.EllipticCurveBrainpoolP192T1;
import de.rub.nds.protocol.crypto.ec.EllipticCurveBrainpoolP224R1;
import de.rub.nds.protocol.crypto.ec.EllipticCurveBrainpoolP224T1;
import de.rub.nds.protocol.crypto.ec.EllipticCurveBrainpoolP256T1;
import de.rub.nds.protocol.crypto.ec.EllipticCurveBrainpoolP320R1;
import de.rub.nds.protocol.crypto.ec.EllipticCurveBrainpoolP320T1;
import de.rub.nds.protocol.crypto.ec.EllipticCurveBrainpoolP384T1;
import de.rub.nds.protocol.crypto.ec.EllipticCurveBrainpoolP512T1;
import de.rub.nds.protocol.crypto.ec.EllipticCurveSECP112R1;
import de.rub.nds.protocol.crypto.ec.EllipticCurveSECP112R2;
import de.rub.nds.protocol.crypto.ec.EllipticCurveSECP128R1;
import de.rub.nds.protocol.crypto.ec.EllipticCurveSECP128R2;
import de.rub.nds.protocol.crypto.ec.EllipticCurveSECT113R1;
import de.rub.nds.protocol.crypto.ec.EllipticCurveSECT113R2;
import de.rub.nds.protocol.crypto.ec.EllipticCurveSECT131R1;
import de.rub.nds.protocol.crypto.ec.EllipticCurveSECT131R2;
import de.rub.nds.protocol.crypto.ec.EllipticCurveSECT163K1;
import de.rub.nds.protocol.crypto.ec.EllipticCurveSECT163R1;
import de.rub.nds.protocol.crypto.ec.EllipticCurveSECT163R2;
import de.rub.nds.protocol.crypto.ec.EllipticCurveSECT193R1;
import de.rub.nds.protocol.crypto.ec.EllipticCurveSECT193R2;
import de.rub.nds.protocol.crypto.ec.EllipticCurveSECT233K1;
import de.rub.nds.protocol.crypto.ec.EllipticCurveSECT233R1;
import de.rub.nds.protocol.crypto.ec.EllipticCurveSECT239K1;
import de.rub.nds.protocol.crypto.ec.EllipticCurveSECT283K1;
import de.rub.nds.protocol.crypto.ec.EllipticCurveSECT283R1;
import de.rub.nds.protocol.crypto.ec.EllipticCurveSECT409K1;
import de.rub.nds.protocol.crypto.ec.EllipticCurveSECT409R1;
import de.rub.nds.protocol.crypto.ec.EllipticCurveSECT571K1;
import de.rub.nds.protocol.crypto.ec.EllipticCurveSECT571R1;

public enum NamedEllipticCurveParameters implements GroupParameters {
    //SECT
    SECT113R1("sect113r1", null, null, "sect113r1", EcCurveEquationType.SHORT_WEIERSTRASS, 113, new EllipticCurveSECT113R1()),
    SECT113R2("sect113r2", null, null, "sect113r2", EcCurveEquationType.SHORT_WEIERSTRASS, 113, new EllipticCurveSECT113R2()),
    SECT131R1("sect131r1", null, null, "sect131r1", EcCurveEquationType.SHORT_WEIERSTRASS, 131, new EllipticCurveSECT131R1()),
    SECT131R2("sect131r2", null, null, "sect131r2", EcCurveEquationType.SHORT_WEIERSTRASS, 131, new EllipticCurveSECT131R2()),
    SECT163K1("sect163k1", null, "NIST K-163", "sect163k1", EcCurveEquationType.SHORT_WEIERSTRASS, 163, new EllipticCurveSECT163K1()),
    SECT163R1("sect163r1", null, null, "sect163r1", EcCurveEquationType.SHORT_WEIERSTRASS, 163, new EllipticCurveSECT163R1()),
    SECT163R2("sect163r2", null, "NIST B-163", "sect163r2", EcCurveEquationType.SHORT_WEIERSTRASS, 163, new EllipticCurveSECT163R2()),
    SECT193R1("sect193r1", null, null, "sect193r1", EcCurveEquationType.SHORT_WEIERSTRASS, 193, new EllipticCurveSECT193R1()),
    SECT193R2("sect193r2", null, null, "sect193r2", EcCurveEquationType.SHORT_WEIERSTRASS, 193, new EllipticCurveSECT193R2()),
    SECT233K1("sect233k1", null, "NIST K-233", "sect233k1", EcCurveEquationType.SHORT_WEIERSTRASS, 233, new EllipticCurveSECT233K1()),
    SECT233R1("sect233r1", null, "NIST B-233", "sect233r1", EcCurveEquationType.SHORT_WEIERSTRASS, 233, new EllipticCurveSECT233R1()),
    SECT239K1("sect239k1", null, null, "sect239k1", EcCurveEquationType.SHORT_WEIERSTRASS, 239, new EllipticCurveSECT239K1()),
    SECT283K1("sect283k1", null, "NIST K-283", "sect283k1", EcCurveEquationType.SHORT_WEIERSTRASS, 283, new EllipticCurveSECT283K1()),
    SECT283R1("sect283r1", null, "NIST B-283", "sect283r1", EcCurveEquationType.SHORT_WEIERSTRASS, 283, new EllipticCurveSECT283R1()),
    SECT409K1("sect409k1", null, "NIST K-409", "sect409k1", EcCurveEquationType.SHORT_WEIERSTRASS, 409, new EllipticCurveSECT409K1()),
    SECT409R1("sect409r1", null, "NIST B-409", "sect409r1", EcCurveEquationType.SHORT_WEIERSTRASS, 409, new EllipticCurveSECT409R1()),
    SECT571K1("sect571k1", null, "NIST K-571", "sect571k1", EcCurveEquationType.SHORT_WEIERSTRASS, 571, new EllipticCurveSECT571K1()),
    SECT571R1("sect571r1", null, "NIST B-571", "sect571r1", EcCurveEquationType.SHORT_WEIERSTRASS, 571, new EllipticCurveSECT571R1()),
    //SECP
    SECP112R1("secp112r1", null, null, "secp112r1", EcCurveEquationType.SHORT_WEIERSTRASS, 112, new EllipticCurveSECP112R1()),
    SECP112R2("secp112r2", null, null, "secp112r2", EcCurveEquationType.SHORT_WEIERSTRASS, 112, new EllipticCurveSECP112R2()),
    SECP128R1("secp128r1", null, null, "secp128r1", EcCurveEquationType.SHORT_WEIERSTRASS, 128, new EllipticCurveSECP128R1()),
    SECP128R2("secp128r2", null, null, "secp128r2", EcCurveEquationType.SHORT_WEIERSTRASS, 128, new EllipticCurveSECP128R2()),
    SECP160K1("secp160k1", null, null, "secp160k1", EcCurveEquationType.SHORT_WEIERSTRASS, 160, new EllipticCurveSECP160K1()),
    SECP160R1("secp160r1", null, null, "secp160r1", EcCurveEquationType.SHORT_WEIERSTRASS, 160, new EllipticCurveSECP160R1()),
    SECP160R2("secp160r2", null, null, "secp160r2", EcCurveEquationType.SHORT_WEIERSTRASS, 150, new EllipticCurveSECP160R2()),
    SECP192K1("secp192k1", null, null, "secp192k1", EcCurveEquationType.SHORT_WEIERSTRASS, 192, new EllipticCurveSECP192K1()),
    SECP192R1("secp192r1", "prime192v1", "NIST P-192", "secp192r1", EcCurveEquationType.SHORT_WEIERSTRASS, 192, new EllipticCurveSECP192R1()),
    SECP224K1("secp224k1", null, null, "secp224k1", EcCurveEquationType.SHORT_WEIERSTRASS, 224, new EllipticCurveSECP224K1()),
    SECP224R1("secp224r1", null, "NIST P-224", "secp224r1", EcCurveEquationType.SHORT_WEIERSTRASS, 224, new EllipticCurveSECP224R1()),
    SECP256K1("secp256k1", null, null, "secp256k1", EcCurveEquationType.SHORT_WEIERSTRASS, 256, new EllipticCurveSECP256K1()),
    SECP256R1("secp256r1", "prime256v1", "NIST P-256", "secp256r1", EcCurveEquationType.SHORT_WEIERSTRASS, 256, new EllipticCurveSECP256R1()),
    SECP384R1("secp384r1", null, "NIST P-384", "secp384r1", EcCurveEquationType.SHORT_WEIERSTRASS, 384, new EllipticCurveSECP384R1()),
    SECP521R1("secp521r1", null, "NIST P-521", "secp521r1", EcCurveEquationType.SHORT_WEIERSTRASS, 521, new EllipticCurveSECP521R1()),
    //BRAINPOOL
    BRAINPOOLP160R1("brainpoolp160r1", null, null, null, EcCurveEquationType.SHORT_WEIERSTRASS, 160, new EllipticCurveBrainpoolP160R1()),
    BRAINPOOLP160T1("brainpoolp160t1", null, null, null, EcCurveEquationType.SHORT_WEIERSTRASS, 160, new EllipticCurveBrainpoolP160T1()),
    BRAINPOOLP192R1("brainpoolp192r1", null, null, null, EcCurveEquationType.SHORT_WEIERSTRASS, 192, new EllipticCurveBrainpoolP192R1()),
    BRAINPOOLP192T1("brainpoolp192t1", null, null, null, EcCurveEquationType.SHORT_WEIERSTRASS, 192, new EllipticCurveBrainpoolP192T1()),
    BRAINPOOLP224R1("brainpoolp224r1", null, null, null, EcCurveEquationType.SHORT_WEIERSTRASS, 224, new EllipticCurveBrainpoolP224R1()),
    BRAINPOOLP224T1("brainpoolp224t1", null, null, null, EcCurveEquationType.SHORT_WEIERSTRASS, 224, new EllipticCurveBrainpoolP224T1()),
    BRAINPOOLP256R1("brainpoolp256r1", null, null, null, EcCurveEquationType.SHORT_WEIERSTRASS, 256, new EllipticCurveBrainpoolP256R1()),
    BRAINPOOLP256T1("brainpoolp256t1", null, null, null, EcCurveEquationType.SHORT_WEIERSTRASS, 256, new EllipticCurveBrainpoolP256T1()),
    BRAINPOOLP320R1("brainpoolp320r1", null, null, null, EcCurveEquationType.SHORT_WEIERSTRASS, 320, new EllipticCurveBrainpoolP320R1()),
    BRAINPOOLP320T1("brainpoolp320t1", null, null, null, EcCurveEquationType.SHORT_WEIERSTRASS, 320, new EllipticCurveBrainpoolP320T1()),
    BRAINPOOLP384R1("brainpoolp384r1", null, null, null, EcCurveEquationType.SHORT_WEIERSTRASS, 384, new EllipticCurveBrainpoolP384R1()),
    BRAINPOOLP384T1("brainpoolp384t1", null, null, null, EcCurveEquationType.SHORT_WEIERSTRASS, 384, new EllipticCurveBrainpoolP384T1()),
    BRAINPOOLP512R1("brainpoolp512r1", null, null, null, EcCurveEquationType.SHORT_WEIERSTRASS, 512, new EllipticCurveBrainpoolP512R1()),
    BRAINPOOLP512T1("brainpoolp512t1", null, null, null, EcCurveEquationType.SHORT_WEIERSTRASS, 512, new EllipticCurveBrainpoolP512T1()),
    //DJB
    CURVE_X25519("CurveX25519", null, null, null, EcCurveEquationType.MONTGOMERY, 256, new EllipticCurve25519()),
    CURVE_X448("CurveX448", null, null, null, EcCurveEquationType.MONTGOMERY, 448, new EllipticCurve25519());

    private String name; //The name referred by us
    private String x962name; //The name referred by ANSI X9.62
    private String nistName; // The name referred by NIST
    private String secName; // The Name reffered by SEC 2
    private EcCurveEquationType equationType;
    private int bitLength;
    private EllipticCurve curve;

    private NamedEllipticCurveParameters(String name, String x962name, String nistName, String secName, EcCurveEquationType equationType, int bitLength, EllipticCurve curve) {
        this.name = name;
        this.x962name = x962name;
        this.nistName = nistName;
        this.secName = secName;
        this.equationType = equationType;
        this.bitLength = bitLength;
        this.curve = curve;
    }

    public EllipticCurve getCurve() {
        return curve;
    }

    public int getBitLength() {
        return bitLength;
    }

    public void setBitLength(int bitLength) {
        this.bitLength = bitLength;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getX962name() {
        return x962name;
    }

    public void setX962name(String x962name) {
        this.x962name = x962name;
    }

    public String getNistName() {
        return nistName;
    }

    public void setNistName(String nistName) {
        this.nistName = nistName;
    }

    public String getSecName() {
        return secName;
    }

    public void setSecName(String secName) {
        this.secName = secName;
    }

    public EcCurveEquationType getEquationType() {
        return equationType;
    }

    public void setEquationType(EcCurveEquationType equationType) {
        this.equationType = equationType;
    }

    @Override
    public int getElementSize() {
        return bitLength;
    }
}
