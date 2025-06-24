/*
 * Protocol-Attacker - A Framework to create Protocol Analysis Tools
 *
 * Copyright 2023-2024 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.protocol.constants;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import org.junit.jupiter.api.Test;

class EcCurveEquationTypeTest {

    @Test
    void testEnumValues() {
        // Test the number of defined types
        assertEquals(3, EcCurveEquationType.values().length);

        // Test existence of each type
        assertEquals(
                EcCurveEquationType.SHORT_WEIERSTRASS,
                EcCurveEquationType.valueOf("SHORT_WEIERSTRASS"));
        assertEquals(EcCurveEquationType.MONTGOMERY, EcCurveEquationType.valueOf("MONTGOMERY"));
        assertEquals(EcCurveEquationType.EDWARDS, EcCurveEquationType.valueOf("EDWARDS"));
    }

    @Test
    void testEnumNamesAndToString() {
        // Test that each enum has valid name and toString
        for (EcCurveEquationType type : EcCurveEquationType.values()) {
            assertNotNull(type.name());
            assertNotNull(type.toString());
        }
    }

    @Test
    void testEnumOrdinals() {
        // Test that ordinals start at 0 and increment by 1
        assertEquals(0, EcCurveEquationType.SHORT_WEIERSTRASS.ordinal());
        assertEquals(1, EcCurveEquationType.MONTGOMERY.ordinal());
        assertEquals(2, EcCurveEquationType.EDWARDS.ordinal());
    }
}
