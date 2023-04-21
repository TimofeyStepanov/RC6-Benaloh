package com.company.crypto.benaloh.algebra.residue.impl;

import com.company.crypto.benaloh.algebra.prime.PrimeCheckerType;
import com.company.crypto.benaloh.algorithm.Benaloh;
import com.company.crypto.benaloh.algorithm.impl.BenalohImpl;
import org.junit.jupiter.api.Test;

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
        assert (Arrays.equals(array, decoded));
    }

    @Test
    void secondTest() {
        Benaloh benaloh = new BenalohImpl(PrimeCheckerType.MILLER_RABIN, 0.999999, 293);
        for (int i = 0; i < 1000; i++) {
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
            if (!Arrays.equals(array, decoded)) {
                assert (false);
            }
        }
        assert (true);
    }

    @Test
    void thirdTest() {
        Benaloh benaloh = new BenalohImpl(PrimeCheckerType.MILLER_RABIN, 0.999999, 293);
        for (int i = 0; i < 100; i++) {
            benaloh.regenerateOpenKey();
            byte[] array = new byte[1];

            for (byte b = -128; b < 127; b++) {
                array[0] = b;
                if (array[array.length - 1] == 0) {
                    array[array.length - 1] = 127;
                }

                byte[] encoded = benaloh.encode(array, benaloh.getOpenKey());
                byte[] decoded = benaloh.decode(encoded);
                if (!Arrays.equals(array, decoded)) {
                    assert (false);
                }
            }
        }
        assert (true);
    }
}