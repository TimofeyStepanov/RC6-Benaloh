package com.company.crypto.benaloh.algebra.discreteLogarithm.impl;

import com.company.crypto.benaloh.algebra.discreteLogarithm.DiscreteLogarithmService;
import com.company.crypto.benaloh.algebra.factorization.impl.PollardRho;
import com.company.crypto.benaloh.algebra.prime.PrimeCheckerFabric;
import com.company.crypto.benaloh.algebra.prime.PrimeCheckerType;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;

class ShanksAlgorithmTest {
    @Test
    void firstTest() {
        DiscreteLogarithmService s2 = new Pollard(
                new PollardRho(PrimeCheckerFabric.getInstance(PrimeCheckerType.MILLER_RABIN))
        );

        BigInteger answer;
        answer = s2.getDiscreteLogarithm(BigInteger.valueOf(3), BigInteger.valueOf(13), BigInteger.valueOf(17));
        System.out.println(answer);
        assert (answer.equals(BigInteger.valueOf(4)));


        answer = s2.getDiscreteLogarithm(BigInteger.valueOf(3), BigInteger.valueOf(11), BigInteger.valueOf(17));
        System.out.println(answer);
        assert (answer.equals(BigInteger.valueOf(7)));


        answer = s2.getDiscreteLogarithm(BigInteger.valueOf(2), BigInteger.valueOf(28), BigInteger.valueOf(37));
        System.out.println(answer);
        assert (answer.equals(BigInteger.valueOf(34)));

    }
}