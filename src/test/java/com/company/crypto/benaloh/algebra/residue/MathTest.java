package com.company.crypto.benaloh.algebra.residue;

import com.company.crypto.benaloh.algebra.factorization.impl.PollardRho;
import com.company.crypto.benaloh.algebra.prime.PrimeCheckerFabric;
import com.company.crypto.benaloh.algebra.prime.PrimeCheckerType;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.List;
import java.util.Random;
import java.util.concurrent.ThreadLocalRandom;

class MathTest {
    @Test
    void firstTest() {
        PollardRho pollardRho = new PollardRho(PrimeCheckerFabric.getInstance(PrimeCheckerType.MILLER_RABIN));
        for (int i = 0; i < 200; i++) {
            BigInteger randomDigit = getRandomDigit(ThreadLocalRandom.current().nextInt(1, 128));
            System.out.println(randomDigit);
            List<BigInteger> list = pollardRho.getAllPrimeMultipliers(randomDigit);

            BigInteger toCheck = BigInteger.ONE;
            for (BigInteger evenDigit : list) {
                System.out.print(evenDigit + " ");
                toCheck = toCheck.multiply(evenDigit);
            }
            System.out.println();

            if (!toCheck.equals(randomDigit)) {
                assert (false);
            }
        }
        assert (true);
    }

    BigInteger getRandomDigit(int length) {
        return new BigInteger(length, new Random());
    }
}