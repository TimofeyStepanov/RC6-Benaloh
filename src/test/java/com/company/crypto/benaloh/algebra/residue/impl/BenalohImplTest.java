package com.company.crypto.benaloh.algebra.residue.impl;

import com.company.crypto.benaloh.algebra.prime.PrimeCheckerType;
import com.company.crypto.benaloh.algorithm.Benaloh;
import com.company.crypto.benaloh.algorithm.impl.BenalohImpl;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.concurrent.ThreadLocalRandom;

class BenalohImplTest {
    @Test
    void firstTest() {
        // Нельзя подавать пустой последний элемент!
        Benaloh benaloh = new BenalohImpl(PrimeCheckerType.SOLOVEY_STRASSEN, 0.999999, 293);
        byte[] array = {-1};
        byte[] encoded = benaloh.encode(array, benaloh.getOpenKey());
        byte[] decoded = benaloh.decode(encoded);

        if (decoded.length > Byte.MAX_VALUE) {
            throw new IllegalStateException("Bigger");
        }
        assert (Arrays.equals(array, decoded));
    }

    @Test
    void secondTest() {
        Benaloh benaloh = new BenalohImpl(PrimeCheckerType.MILLER_RABIN, 0.999999, 293);
        for (int i = 0; i < 10000; i++) {
            if (i % 10 == 0) {
                benaloh.regenerateOpenKey();
            }
            byte[] array = new byte[1];
            array[0] = (byte) ThreadLocalRandom.current().nextInt();

            if (array[array.length - 1] == 0) {
                array[array.length - 1] = 127;
            }

            byte[] encoded = benaloh.encode(array, benaloh.getOpenKey());
            byte[] decoded = benaloh.decode(encoded);

            if (decoded.length > Byte.MAX_VALUE) {
                throw new IllegalStateException("Bigger");
            }

            if (!Arrays.equals(array, decoded)) {
                assert (false);
            }
        }
        assert (true);
    }

    @Test
    void thirdTest() {
        Benaloh benaloh = new BenalohImpl(PrimeCheckerType.MILLER_RABIN, 0.999999, 293);
        for (int i = 0; i < 1000; i++) {
            benaloh.regenerateOpenKey();
            byte[] array = new byte[1];

            for (byte b = Byte.MIN_VALUE; b < Byte.MAX_VALUE; b++) {
                array[0] = b;
                if (array[array.length - 1] == 0) {
                    array[array.length - 1] = 127;
                }

                byte[] encoded = benaloh.encode(array, benaloh.getOpenKey());
                byte[] decoded = benaloh.decode(encoded);

                if (decoded.length > Byte.MAX_VALUE) {
                    throw new IllegalStateException("Bigger");
                }

                if (!Arrays.equals(array, decoded)) {
                    assert (false);
                }
            }

            byte b = Byte.MAX_VALUE;
            array[0] = b;
            if (array[array.length - 1] == 0) {
                array[array.length - 1] = 127;
            }

            byte[] encoded = benaloh.encode(array, benaloh.getOpenKey());
            byte[] decoded = benaloh.decode(encoded);

            if (decoded.length > Byte.MAX_VALUE) {
                throw new IllegalStateException("Bigger");
            }

            if (!Arrays.equals(array, decoded)) {
                assert (false);
            }
        }

        assert (true);
    }

    @Test
    void mistakeFromServer() {
        // y = 3385026758801912130836561637248371593418984
        // r = 293
        // n = 19798529209034984354678214819411649909788590730532857037515467

        // f = 19798529209034984354678126804455400760523403071185039232897560
        // x = 12266036790272625891941663535101411494106155843925326968436061
    }
}