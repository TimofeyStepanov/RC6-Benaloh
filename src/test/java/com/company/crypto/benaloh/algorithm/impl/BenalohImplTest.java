package com.company.crypto.benaloh.algorithm.impl;

import com.company.crypto.benaloh.algebra.prime.PrimeCheckerType;
import com.company.crypto.benaloh.algorithm.Benaloh;
import org.junit.jupiter.api.Test;

import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

class BenalohImplTest {
    @Test
    void firstTest() {
        Benaloh benaloh = new BenalohImpl(PrimeCheckerType.MILLER_RABIN, 0.999999, 10);
        byte[] array = {1, 9, 12, -1, 9};
        byte[] encoded = benaloh.encode(array, benaloh.getOpenKey());
        byte[] decoded = benaloh.decode(encoded);
        assert (Arrays.equals(array, decoded));
    }
}