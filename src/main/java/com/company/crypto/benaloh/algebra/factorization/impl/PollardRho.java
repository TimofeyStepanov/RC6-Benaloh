package com.company.crypto.benaloh.algebra.factorization.impl;

import com.company.crypto.benaloh.algebra.factorization.FactorizationService;
import com.company.crypto.benaloh.algebra.prime.PrimeChecker;
import lombok.RequiredArgsConstructor;

import java.math.BigInteger;
import java.util.*;
import java.util.stream.Stream;

@RequiredArgsConstructor
public final class PollardRho implements FactorizationService {
    private static final double PRECISION = 0.99999999999999;
    private final PrimeChecker primeChecker;

    @Override
    public List<BigInteger> getAllPrimeMultipliers(BigInteger digit) {
        return this.getFactorList(digit);
    }

    private List<BigInteger> getFactorList(BigInteger digit) {
        if (digit.equals(BigInteger.valueOf(-1)) || digit.equals(BigInteger.ONE) || digit.equals(BigInteger.ZERO)) {
            return Stream.of(digit).toList();
        }

        List<BigInteger> factors = new ArrayList<>();
        getFactor(digit, factors);
        return factors;
    }

    private void getFactor(BigInteger digit, Collection<BigInteger> factors) {
        do {
            if (primeChecker.isPrime(digit, PRECISION)) {
                factors.add(digit);
                return;
            }
            BigInteger divisor = getDivisor(digit);
            factors.add(divisor);
            digit = digit.divide(divisor);
        } while (!digit.equals(BigInteger.ONE));
    }

    private BigInteger getDivisor(BigInteger digit) {
        if (digit.mod(BigInteger.TWO).equals(BigInteger.ZERO)) {
            return BigInteger.TWO;
        }

        BigInteger x1 = BigInteger.TWO;
        BigInteger x2 = BigInteger.TWO;
        BigInteger divisor;
        do
        {
            x1 = countFunction(x1).mod(digit);
            x2 = countFunction(countFunction(x2)).mod(digit);
            BigInteger x1MinusX2 = x1.subtract(x2);
            if (x1MinusX2.signum() < 0) {
                x1MinusX2 = x1MinusX2.negate();
            }
            divisor = getGCD(x1MinusX2, digit);
        } while (divisor.equals(BigInteger.ONE));
        return divisor;
    }

    private BigInteger getGCD(BigInteger firstDigit, BigInteger secondDigit) {
        if (secondDigit.equals(BigInteger.ZERO)) {
            return firstDigit;
        }
        return getGCD(secondDigit, firstDigit.mod(secondDigit));
    }

    private BigInteger countFunction(BigInteger digit) {
        return digit.multiply(digit).add(BigInteger.ONE);
    }


    @Override
    public Set<BigInteger> getUniquePrimeMultipliers(BigInteger digit) {
        return this.getFactorSet(digit);
    }

    private Set<BigInteger> getFactorSet(BigInteger digit) {
        if (digit.equals(BigInteger.ONE)) {
            return new HashSet<>();
        }

        Set<BigInteger> factors = new HashSet<>();
        getFactor(digit, factors);
        return factors;
    }
}