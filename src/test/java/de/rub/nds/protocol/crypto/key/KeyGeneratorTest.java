package de.rub.nds.protocol.crypto.key;

import java.util.Random;

import org.junit.jupiter.api.Test;

public class KeyGeneratorTest {

    @Test
    void testGenerateRsaKeys() {
        for (int i = 6; i < 4096; i = i + 123) {
            KeyGenerator.generateRsaKeys(i, new Random());
        }
    }
}
