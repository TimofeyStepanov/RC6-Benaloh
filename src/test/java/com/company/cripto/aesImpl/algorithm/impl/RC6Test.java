package com.company.cripto.aesImpl.algorithm.impl;

import com.company.cripto.aesImpl.round.impl.RoundKeysGeneratorRC6;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.concurrent.ThreadLocalRandom;


class RC6Test {
    RC6 rc6 = RC6.getInstance(
            new RoundKeysGeneratorRC6(32, 20, RC6.CipherKeyLength.BIT_128)
    );

    @Test
    void checkTranslator() {
        byte[] input = new byte[128 / 8];
        for (int j = 0; j < 1000; j++) {
            for (int i = 0; i < input.length; i++) {
                input[i] = (byte) ThreadLocalRandom.current().nextInt();
            }

            byte[] output = new byte[input.length];

            int[] ar1 = rc6.translateInputByteArrayIntArray(input);
            rc6.translateIntArrayToByteArray(ar1, output);

            if (!Arrays.equals(input, output)) {
                assert (false);
            }
        }
        assert (true);
    }

    @Test
    void test128() {
        rc6 = RC6.getInstance(
                new RoundKeysGeneratorRC6(32, 20, RC6.CipherKeyLength.BIT_128)
        );

        int keyLength = RC6.CipherKeyLength.BIT_128.bitsNumber;

        for (int j = 0; j < 1000; j++) {
            byte[] input = new byte[128 / 8];
            for (int i = 0; i < input.length; i++) {
                input[i] = (byte) ThreadLocalRandom.current().nextInt();
            }

            byte[] cipherKey = new byte[keyLength / 8];
            for (int i = 0; i < cipherKey.length; i++) {
                cipherKey[i] = (byte) ThreadLocalRandom.current().nextInt();
            }
            rc6.setKey(cipherKey);

            byte[] encoded = rc6.encode(input.clone());
            byte[] decoded = rc6.decode(encoded.clone());

            assert (Arrays.equals(input, decoded));
        }
    }

    @Test
    void test192() {
        rc6 = RC6.getInstance(
                new RoundKeysGeneratorRC6(32, 20, RC6.CipherKeyLength.BIT_192)
        );

        int keyLength = RC6.CipherKeyLength.BIT_192.bitsNumber;

        for (int j = 0; j < 1000; j++) {
            byte[] input = new byte[128 / 8];
            for (int i = 0; i < input.length; i++) {
                input[i] = (byte) ThreadLocalRandom.current().nextInt();
            }

            byte[] cipherKey = new byte[keyLength / 8];
            for (int i = 0; i < cipherKey.length; i++) {
                cipherKey[i] = (byte) ThreadLocalRandom.current().nextInt();
            }
            rc6.setKey(cipherKey);

            byte[] encoded = rc6.encode(input.clone());
            byte[] decoded = rc6.decode(encoded.clone());

            assert (Arrays.equals(input, decoded));
        }
    }

    @Test
    void test256() {
        rc6 = RC6.getInstance(
                new RoundKeysGeneratorRC6(32, 20, RC6.CipherKeyLength.BIT_256)
        );

        int keyLength = RC6.CipherKeyLength.BIT_256.bitsNumber;

        for (int j = 0; j < 1000; j++) {
            byte[] input = new byte[128 / 8];
            for (int i = 0; i < input.length; i++) {
                input[i] = (byte) ThreadLocalRandom.current().nextInt();
            }

            byte[] cipherKey = new byte[keyLength / 8];
            for (int i = 0; i < cipherKey.length; i++) {
                cipherKey[i] = (byte) ThreadLocalRandom.current().nextInt();
            }
            rc6.setKey(cipherKey);

            byte[] encoded = rc6.encode(input.clone());
            byte[] decoded = rc6.decode(encoded.clone());

            assert (Arrays.equals(input, decoded));
        }
    }

}