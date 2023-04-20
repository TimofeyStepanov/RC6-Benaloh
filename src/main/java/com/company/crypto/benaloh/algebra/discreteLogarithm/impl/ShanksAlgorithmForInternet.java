package com.company.crypto.benaloh.algebra.discreteLogarithm.impl;

import com.company.crypto.benaloh.algebra.discreteLogarithm.DiscreteLogarithmService;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

@Deprecated
public final class ShanksAlgorithmForInternet implements DiscreteLogarithmService {
    private static final BigInteger MINUS_ONE = BigInteger.valueOf(-1);
    private static final BigInteger ZERO = BigInteger.valueOf(0) ;
    private static final BigInteger ONE = BigInteger.valueOf(1);
    private static final BigInteger TWO = BigInteger.valueOf(2);

    @Override
    public BigInteger getDiscreteLogarithm(BigInteger base, BigInteger arg, BigInteger modulo) {
        return calculate(base, modulo, arg);
    }

    private BigInteger calculate(BigInteger logBase, BigInteger modulus, BigInteger result) {
        if (result.compareTo(modulus) == 0) {
            throw new ArithmeticException("If x = p then solution does not exist");
        }

        final BigInteger k = sqrt(modulus);
        final BigInteger maxIteratorValue = k.subtract(ONE);
        final List<BigInteger> babySteps = new ArrayList<>();

        generateBabySteps(babySteps, maxIteratorValue, modulus, result, logBase);

        for (BigInteger j = ONE; j.compareTo(maxIteratorValue) < 1; j = j.add(ONE)) {
            BigInteger multiplied = j.multiply(k);
            BigInteger giantStep = logBase.modPow(multiplied, modulus);
            BigInteger i = matchBabyStep(babySteps, maxIteratorValue, giantStep);
            if (i.compareTo(MINUS_ONE) > 0) {
                BigInteger sub = new BigInteger("-" + i.toString());
                return j.multiply(k).add(sub);
            }
        }
        throw new ArithmeticException();
    }

    private BigInteger sqrt(BigInteger x) {
        if (x.compareTo(ZERO) < 0) {
            throw new IllegalArgumentException("Negative argument.");
        }
        if (x.equals(ZERO) || x.equals(ONE)) {
            return x;
        }

        BigInteger two = TWO;
        BigInteger y;
        for (y = x.divide(two); y.compareTo(x.divide(y)) > 0; y = ((x.divide(y)).add(y)).divide(two));
        if (x.compareTo(y.multiply(y)) == 0) {
            return y;
        } else {
            return y.add(BigInteger.ONE);
        }
    }

    private void generateBabySteps(List<BigInteger> babySteps, BigInteger maxIteratorValue,
                                   BigInteger modulus, BigInteger result, BigInteger logBase) {
        for (BigInteger i = ZERO; i.compareTo(maxIteratorValue) < 1; i = i.add(ONE)){
            BigInteger pow = logBase.modPow(i, modulus);
            BigInteger res = result.multiply(pow).mod(modulus);
            babySteps.add(res);
        }
    }

    private BigInteger matchBabyStep(List<BigInteger> babySteps, BigInteger maxIteratorValue, BigInteger giantStep) {
        for (BigInteger i = ZERO; i.compareTo(maxIteratorValue) < 1; i = i.add(ONE)) {
            BigInteger babyStep = babySteps.get(i.intValue());
            if (babyStep.compareTo(giantStep) == 0) {
                return i;
            }
        }
        return MINUS_ONE;
    }
}
