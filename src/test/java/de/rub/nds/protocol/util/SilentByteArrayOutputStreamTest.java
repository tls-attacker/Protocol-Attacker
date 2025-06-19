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
import java.io.IOException;
import java.io.OutputStream;
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

    @Test
    public void testConstructorWithNegativeSize() {
        assertThrows(IllegalArgumentException.class, () -> new SilentByteArrayOutputStream(-1));
    }

    @Test
    public void testWriteByteArrayNull() {
        assertThrows(NullPointerException.class, () -> stream.write((byte[]) null));
    }

    @Test
    public void testWriteByteArrayWithOffsetNull() {
        assertThrows(NullPointerException.class, () -> stream.write(null, 0, 0));
    }

    @Test
    public void testWriteByteArrayWithNegativeOffset() {
        byte[] data = {0x01, 0x02, 0x03};
        assertThrows(IndexOutOfBoundsException.class, () -> stream.write(data, -1, 2));
    }

    @Test
    public void testWriteByteArrayWithNegativeLength() {
        byte[] data = {0x01, 0x02, 0x03};
        assertThrows(IndexOutOfBoundsException.class, () -> stream.write(data, 0, -1));
    }

    @Test
    public void testWriteByteArrayWithLengthExceedingBounds() {
        byte[] data = {0x01, 0x02, 0x03};
        assertThrows(IndexOutOfBoundsException.class, () -> stream.write(data, 1, 3));
    }

    @Test
    public void testWriteBytesNull() {
        assertThrows(NullPointerException.class, () -> stream.writeBytes(null));
    }

    @Test
    public void testWriteToNull() {
        stream.write(new byte[] {0x01, 0x02});
        assertThrows(NullPointerException.class, () -> stream.writeTo(null));
    }

    @Test
    public void testToStringWithInvalidCharsetName() {
        stream.write("Test".getBytes(StandardCharsets.UTF_8));
        assertThrows(IllegalArgumentException.class, () -> stream.toString("INVALID-CHARSET"));
    }

    @Test
    public void testMultipleOperationsAfterClose() {
        stream.write(new byte[] {0x01, 0x02});
        stream.close();

        // All operations should work after close
        stream.write(0x03);
        stream.write(new byte[] {0x04, 0x05});
        stream.writeBytes(new byte[] {0x06, 0x07});
        assertEquals(7, stream.size());

        byte[] result = stream.toByteArray();
        assertArrayEquals(new byte[] {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}, result);

        stream.reset();
        assertEquals(0, stream.size());
    }

    @Test
    public void testWriteToWithIOException() {
        stream.write(new byte[] {0x01, 0x02});

        // Create an OutputStream that throws IOException
        OutputStream failingOutputStream =
                new OutputStream() {
                    @Override
                    public void write(int b) throws IOException {
                        throw new IOException("Test exception");
                    }
                };

        assertThrows(RuntimeException.class, () -> stream.writeTo(failingOutputStream));
    }
}
