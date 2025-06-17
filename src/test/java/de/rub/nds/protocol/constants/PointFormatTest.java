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

public class PointFormatTest {

    @Test
    public void testEnumValues() {
        // Test the number of defined point formats
        assertEquals(2, PointFormat.values().length);

        // Test existence of each point format
        assertEquals(PointFormat.UNCOMPRESSED, PointFormat.valueOf("UNCOMPRESSED"));
        assertEquals(PointFormat.COMPRESSED, PointFormat.valueOf("COMPRESSED"));
    }

    @Test
    public void testEnumNamesAndToString() {
        // Test that each enum has valid name and toString
        for (PointFormat format : PointFormat.values()) {
            assertNotNull(format.name());
            assertNotNull(format.toString());
        }
    }

    @Test
    public void testEnumOrdinals() {
        // Test that ordinals start at 0 and increment by 1
        assertEquals(0, PointFormat.UNCOMPRESSED.ordinal());
        assertEquals(1, PointFormat.COMPRESSED.ordinal());
    }

    @Test
    public void testValueOfMethod() {
        // Test valueOf with both values
        assertEquals(PointFormat.UNCOMPRESSED, PointFormat.valueOf("UNCOMPRESSED"));
        assertEquals(PointFormat.COMPRESSED, PointFormat.valueOf("COMPRESSED"));
    }
}
