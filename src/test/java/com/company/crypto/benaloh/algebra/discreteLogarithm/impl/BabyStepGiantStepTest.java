package com.company.crypto.benaloh.algebra.discreteLogarithm.impl;

import com.company.crypto.benaloh.algebra.discreteLogarithm.DiscreteLogarithmService;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;

import static org.junit.jupiter.api.Assertions.*;

class BabyStepGiantStepTest {
    @Test
    void firstTest() {
        DiscreteLogarithmService service = new BabyStepGiantStep();

        BigInteger base = BigInteger.valueOf(445972307889L);
        BigInteger arg = BigInteger.valueOf(381233043736L);
        BigInteger modulo = BigInteger.valueOf(479568059923L);

        BigInteger answer = service.getDiscreteLogarithm(base, arg, modulo);

        System.out.println(base.modPow(answer, modulo).equals(arg));
        System.out.println(base.modPow(BigInteger.valueOf(246), modulo).equals(arg));

    }
}