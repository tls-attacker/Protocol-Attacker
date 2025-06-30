/*
 * Protocol-Attacker - A Framework to create Protocol Analysis Tools
 *
 * Copyright 2023-2025 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.protocol.util;

import static org.junit.jupiter.api.Assertions.*;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class SilentByteArrayOutputStreamTest {

    private SilentByteArrayOutputStream stream;

    @BeforeEach
    void setUp() {
        stream = new SilentByteArrayOutputStream();
    }

    @Test
    void testDefaultConstructor() {
        assertNotNull(stream);
        assertEquals(0, stream.size());
    }

    @Test
    void testSizedConstructor() {
        try (SilentByteArrayOutputStream sizedStream = new SilentByteArrayOutputStream(64)) {
            assertNotNull(sizedStream);
            assertEquals(0, sizedStream.size());
        }
    }

    @Test
    void testWriteSingleByte() {
        stream.write(0x04);
        assertEquals(1, stream.size());
        assertEquals((byte) 0x04, stream.toByteArray()[0]);
    }

    @Test
    void testWriteByteArray() {
        byte[] data = {0x01, 0x02, 0x03, 0x04};
        stream.write(data);
        assertEquals(4, stream.size());
        assertArrayEquals(data, stream.toByteArray());
    }

    @Test
    void testWriteByteArrayWithOffsetAndLength() {
        byte[] data = {0x01, 0x02, 0x03, 0x04};
        stream.write(data, 1, 2);
        assertArrayEquals(new byte[] {0x02, 0x03}, stream.toByteArray());
    }

    @Test
    void testWriteBytes() {
        byte[] data = {0x01, 0x02, 0x03, 0x04};
        stream.writeBytes(data);
        assertArrayEquals(data, stream.toByteArray());
    }

    @Test
    void testWriteTo() {
        byte[] data = {0x01, 0x02, 0x03, 0x04};
        stream.write(data);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        stream.writeTo(out);
        assertArrayEquals(data, out.toByteArray());
    }

    @Test
    void testReset() {
        byte[] data = {0x01, 0x02, 0x03, 0x04};
        stream.write(data);
        assertEquals(4, stream.size());
        stream.reset();
        assertEquals(0, stream.size());
    }

    @Test
    void testToByteArray() {
        stream.write(new byte[] {0x01, 0x02});
        byte[] result = stream.toByteArray();
        assertArrayEquals(new byte[] {0x01, 0x02}, result);
    }

    @Test
    void testToStringDefaultCharset() {
        String testString = "Test";
        stream.write(testString.getBytes(StandardCharsets.UTF_8));
        assertEquals(testString, stream.toString());
    }

    @Test
    void testToStringWithCharsetName() {
        String testString = "Test";
        stream.write(testString.getBytes(StandardCharsets.UTF_8));
        assertEquals(testString, stream.toString("UTF-8"));
    }

    @Test
    void testToStringWithCharset() {
        String testString = "Test";
        stream.write(testString.getBytes(StandardCharsets.UTF_8));
        assertEquals(testString, stream.toString(StandardCharsets.UTF_8));
    }

    @Test
    @SuppressWarnings("deprecation")
    void testToStringWithHighByte() {
        stream.write(new byte[] {0x54, 0x65, 0x73, 0x74}); // Test
        String result = stream.toString(0);
        assertEquals(4, result.length());
    }

    @Test
    void testCloseDoesNothing() {
        stream.write(0x01);
        assertDoesNotThrow(() -> stream.close());
        stream.write(0x02);
        assertEquals(2, stream.size());
    }
}
