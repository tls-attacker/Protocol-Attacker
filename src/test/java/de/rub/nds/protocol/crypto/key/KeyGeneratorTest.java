package de.rub.nds.protocol.crypto.key;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Random;

import org.apache.commons.lang3.tuple.Pair;
import org.junit.jupiter.api.Test;

public class KeyGeneratorTest {

    @Test
    void testGenerateRsaKeys() {
        for (int i = 12; i < 4096; i = i + 123) {
            Pair<RsaPublicKey, RsaPrivateKey> rsaKeys = KeyGenerator.generateRsaKeys(i, new Random());
            assertTrue(rsaKeys.getLeft().getModulus().bitLength() == i);
        }
    }
}
