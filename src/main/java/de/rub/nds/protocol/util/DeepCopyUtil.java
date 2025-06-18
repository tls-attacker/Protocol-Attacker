/*
 * Protocol-Attacker - A Framework to create Protocol Analysis Tools
 *
 * Copyright 2023-2024 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.protocol.util;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

/**
 * Utility class for creating deep copies of serializable objects through serialization.
 * Uses Java serialization mechanism to create independent copies of complex object graphs.
 */
public class DeepCopyUtil {
    private DeepCopyUtil() {}

    /**
     * Creates a deep copy of the given object using serialization.
     *
     * <p>This method performs a deep copy by serializing the object to a byte array and then
     * deserializing it back to create a new instance. All nested objects will be copied as well,
     * provided they are serializable.
     *
     * @param <T> the type of the object to copy
     * @param object the object to be deep copied
     * @return a deep copy of the provided object
     * @throws RuntimeException if the object is not serializable or if an I/O error occurs
     */
    public static <T> T deepCopy(T object) {
        try {
            SilentByteArrayOutputStream outputStream = new SilentByteArrayOutputStream();
            ObjectOutputStream objectOutputStream = new ObjectOutputStream(outputStream);
            objectOutputStream.writeObject(object);
            objectOutputStream.flush();
            objectOutputStream.close();

            ByteArrayInputStream inputStream = new ByteArrayInputStream(outputStream.toByteArray());
            ObjectInputStream objectInputStream = new ObjectInputStream(inputStream);
            @SuppressWarnings("unchecked")
            T copy = (T) objectInputStream.readObject();
            objectInputStream.close();

            return copy;
        } catch (IOException | ClassNotFoundException e) {
            throw new RuntimeException(e);
        }
    }
}
