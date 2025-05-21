/*
 * Protocol-Attacker - A Framework to create Protocol Analysis Tools
 *
 * Copyright 2023-2024 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.protocol.util;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.nio.charset.Charset;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * A wrapper around {@link ByteArrayOutputStream} that suppresses IOExceptions in most operations
 * and logs them silently.
 */
public class SilentByteArrayOutputStream extends OutputStream {

    private static final Logger LOGGER = LogManager.getLogger();
    private final ByteArrayOutputStream outputStream;

    /**
     * Creates a new {@code SilentByteArrayOutputStream}. The buffer capacity is initially 32 bytes,
     * though its size increases if necessary.
     */
    public SilentByteArrayOutputStream() {
        this.outputStream = new ByteArrayOutputStream(32);
    }

    /**
     * Creates a new {@code ByteArrayOutputStream}, with a buffer capacity of the specified size, in
     * bytes.
     *
     * @param size the initial size.
     * @throws IllegalArgumentException if size is negative.
     */
    public SilentByteArrayOutputStream(int size) {
        this.outputStream = new ByteArrayOutputStream(size);
    }

    /**
     * Writes the specified byte to this {@code SilentByteArrayOutputStream}.
     *
     * @param b the byte to be written.
     */
    @Override
    public void write(int b) {
        this.outputStream.write(b);
    }

    /**
     * Writes {@code b.length} bytes from the specified byte array to this output stream. The
     * general contract for {@code write(b)} is that it should have exactly the same effect as the
     * call {@code write(b, 0, b.length)}.
     *
     * <p>This method does not throw IOException, it logs instead.
     *
     * @param b the data.
     * @see java.io.OutputStream#write(byte[], int, int)
     */
    @Override
    public void write(byte[] b) {
        try {
            this.outputStream.write(b);
        } catch (IOException ex) {
            LOGGER.warn("Encountered exception while writing to ByteArrayOutputStream.");
            LOGGER.debug(ex);
        }
    }

    /**
     * Writes {@code len} bytes from the specified byte array starting at offset {@code off} to this
     * {@code SilentByteArrayOutputStream}.
     *
     * @param b {@inheritDoc}
     * @param off {@inheritDoc}
     * @param len {@inheritDoc}
     * @throws NullPointerException if {@code b} is {@code null}.
     * @throws IndexOutOfBoundsException if {@code off} is negative, {@code len} is negative, or
     *     {@code len} is greater than {@code b.length - off}
     */
    @Override
    public void write(byte[] b, int off, int len) {
        this.outputStream.write(b, off, len);
    }

    /**
     * Writes the complete contents of the specified byte array to this {@code
     * SilentByteArrayOutputStream}.
     *
     * <p>This method is equivalent to {@link #write(byte[],int,int) write(b, 0, b.length)}.
     *
     * @param b the data.
     * @throws NullPointerException if {@code b} is {@code null}.
     * @since 11
     */
    public void writeBytes(byte[] b) {
        write(b, 0, b.length);
    }

    /**
     * Writes the complete contents of this {@code SilentByteArrayOutputStream} to the specified
     * output stream argument, as if by calling the output stream's write method using {@code
     * out.write(buf, 0, count)}.
     *
     * <p>This method does not throw IOException, it logs instead.
     *
     * @param out the output stream to which to write the data.
     * @throws NullPointerException if {@code out} is {@code null}.
     */
    public void writeTo(OutputStream out) {
        try {
            this.outputStream.writeTo(out);
        } catch (IOException ex) {
            LOGGER.warn("Encountered exception while writing to OutputStream.");
            LOGGER.debug(ex);
        }
    }

    /**
     * Resets the {@code count} field of this {@code SilentByteArrayOutputStream} to zero, so that
     * all currently accumulated output in the output stream is discarded. The output stream can be
     * used again, reusing the already allocated buffer space.
     */
    public void reset() {
        this.outputStream.reset();
    }

    /**
     * Creates a newly allocated byte array. Its size is the current size of this output stream and
     * the valid contents of the buffer have been copied into it.
     *
     * @return the current contents of this output stream, as a byte array.
     * @see java.io.ByteArrayOutputStream#size()
     */
    public byte[] toByteArray() {
        return this.outputStream.toByteArray();
    }

    /**
     * Returns the current size of the buffer.
     *
     * @return the value of the {@code count} field, which is the number of valid bytes in this
     *     output stream.
     */
    public int size() {
        return this.outputStream.size();
    }

    /**
     * Converts the buffer's contents into a string decoding bytes using the default charset. The
     * length of the new {@code String} is a function of the charset, and hence may not be equal to
     * the size of the buffer.
     *
     * <p>This method always replaces malformed-input and unmappable-character sequences with the
     * default replacement string for the default charset. The {@linkplain
     * java.nio.charset.CharsetDecoder} class should be used when more control over the decoding
     * process is required.
     *
     * @see Charset#defaultCharset()
     * @return String decoded from the buffer's contents.
     * @since 1.1
     */
    @Override
    public String toString() {
        return this.outputStream.toString();
    }

    /**
     * Converts the buffer's contents into a string by decoding the bytes using the named {@link
     * Charset charset}.
     *
     * <p>This method is equivalent to {@code #toString(charset)} that takes a {@link Charset
     * charset}.
     *
     * <p>An invocation of this method of the form
     *
     * {@snippet lang=java :
     *     ByteArrayOutputStream b;
     *     b.toString("UTF-8")
     * }
     *
     * behaves in exactly the same way as the expression
     *
     * {@snippet lang=java :
     *     ByteArrayOutputStream b;
     *     b.toString(StandardCharsets.UTF_8)
     * }
     *
     * @param charsetName the name of a supported {@link Charset charset}
     * @return String decoded from the buffer's contents.
     * @throws IllegalArgumentException If the named charset is not supported
     * @since 1.1
     */
    public String toString(String charsetName) {
        try {
            return this.outputStream.toString(charsetName);
        } catch (UnsupportedEncodingException ex) {
            LOGGER.warn("Unsupported encoding: {}", charsetName);
            LOGGER.debug(ex);
            throw new IllegalArgumentException("Unsupported encoding: " + charsetName, ex);
        }
    }

    /**
     * Converts the buffer's contents into a string by decoding the bytes using the specified {@link
     * Charset charset}. The length of the new {@code String} is a function of the charset, and
     * hence may not be equal to the length of the byte array.
     *
     * <p>This method always replaces malformed-input and unmappable-character sequences with the
     * charset's default replacement string. The {@link java.nio.charset.CharsetDecoder} class
     * should be used when more control over the decoding process is required.
     *
     * @param charset the {@linkplain Charset charset} to be used to decode the {@code bytes}
     * @return String decoded from the buffer's contents.
     * @since 10
     */
    public String toString(Charset charset) {
        return this.outputStream.toString(charset);
    }

    /**
     * Creates a newly allocated string. Its size is the current size of the output stream and the
     * valid contents of the buffer have been copied into it. Each character <i>c</i> in the
     * resulting string is constructed from the corresponding element <i>b</i> in the byte array
     * such that:
     *
     * {@snippet lang=java :
     *     c == (char)(((hibyte & 0xff) << 8) | (b & 0xff))
     * }
     *
     * @deprecated This method does not properly convert bytes into characters. As of JDK&nbsp;1.1,
     *     the preferred way to do this is via the {@link #toString(String charsetName)} or {@link
     *     #toString(Charset charset)} method, which takes an encoding-name or charset argument, or
     *     the {@code toString()} method, which uses the default charset.
     * @param hibyte the high byte of each resulting Unicode character.
     * @return the current contents of the output stream, as a string.
     * @see java.io.ByteArrayOutputStream#size()
     * @see java.io.ByteArrayOutputStream#toString(String)
     * @see java.io.ByteArrayOutputStream#toString()
     * @see Charset#defaultCharset()
     */
    @Deprecated
    public String toString(int hibyte) {
        return this.outputStream.toString(hibyte);
    }

    /**
     * Closing a {@code SilentByteArrayOutputStream} has no effect. The methods in this class can be
     * called after the stream has been closed without generating an {@code IOException}.
     */
    @Override
    public void close() {}
}
