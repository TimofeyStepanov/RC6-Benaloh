package com.company.crypto.benaloh.algebra.discreteLogarithm.impl;

import com.company.crypto.benaloh.algebra.discreteLogarithm.DiscreteLogarithmService;
import com.company.crypto.benaloh.algebra.factorization.FactorizationService;
import lombok.AllArgsConstructor;
import lombok.RequiredArgsConstructor;

import java.math.BigInteger;
import java.util.Map;

@Deprecated
@RequiredArgsConstructor
public final class Pollard implements DiscreteLogarithmService {
    @AllArgsConstructor
    private class EEATuple {
        BigInteger d;
        BigInteger x;
        BigInteger y;
    }

    private final FactorizationService factorizationService;

    @Override
    public BigInteger getDiscreteLogarithm(BigInteger base, BigInteger arg, BigInteger modulo) {
        if (base.equals(arg)) {
            return BigInteger.ONE;
        }
        BigInteger THREE = BigInteger.valueOf(3);
        BigInteger n = eulerFunction(modulo);

        BigInteger a1 = BigInteger.ZERO;
        BigInteger a2 = BigInteger.ZERO;

        BigInteger b1 = BigInteger.ZERO;
        BigInteger b2 = BigInteger.ZERO;

        BigInteger x1 = BigInteger.ONE;
        BigInteger x2 = BigInteger.ONE;
        do {
            if (x1.compareTo(modulo.divide(THREE)) < 0) {
                x1 = arg.multiply(x1).mod(modulo);
                b1 = b1.add(BigInteger.ONE).mod(n);
            } else if (x1.compareTo(modulo.divide(THREE)) >= 0
                    && x1.compareTo(modulo.divide(THREE).multiply(BigInteger.TWO)) < 0) {
                x1 = x1.multiply(x1).mod(modulo);
                a1 = a1.multiply(BigInteger.TWO).mod(n);
                b1 = b1.multiply(BigInteger.TWO).mod(n);
            } else {
                x1 = base.multiply(x1).mod(modulo);
                a1 = a1.add(BigInteger.ONE).mod(n);
            }

            for (int i = 0; i < 2; i++) {
                if (x2.compareTo(modulo.divide(THREE)) < 0) {
                    x2 = arg.multiply(x2).mod(modulo);
                    b2 = b2.add(BigInteger.ONE).mod(n);
                } else if (x2.compareTo(modulo.divide(THREE)) >= 0
                        && x2.compareTo(modulo.divide(THREE).multiply(BigInteger.TWO)) < 0) {
                    x2 = x2.multiply(x2).mod(modulo);
                    a2 = a2.multiply(BigInteger.TWO).mod(n);
                    b2 = b2.multiply(BigInteger.TWO).mod(n);
                } else {
                    x2 = base.multiply(x2).mod(modulo);
                    a2 = a2.add(BigInteger.ONE).mod(n);
                }
            }
        } while (!x1.equals(x2));

        BigInteger u = a1.subtract(a2).mod(n);
        BigInteger v = b2.subtract(b1).mod(n);

        if (v.mod(n).equals(BigInteger.ZERO)) {
            throw new IllegalArgumentException("Can't find log");
        }

        EEATuple eeaTuple = EEA(v, n);
        BigInteger d = eeaTuple.d;
        BigInteger nu = eeaTuple.x;

        BigInteger x = null;
        BigInteger i = BigInteger.ZERO;
        BigInteger dPlusOne = d.add(BigInteger.ONE);
        while (!i.equals(dPlusOne)) {
            x = u.multiply(nu).add(i.multiply(n)).divide(d).mod(n);
            if (BigInteger.ZERO.equals(pow(base, x).min(arg).mod(modulo))) {
                return x;
            }
            i = i.add(BigInteger.ONE);
        }

        if (x == null) {
            throw new IllegalArgumentException("Can't find log");
        }
        return x;
    }

    private BigInteger eulerFunction(BigInteger digit) {
        if (digit.compareTo(BigInteger.ONE) <= 0) {
            throw new IllegalArgumentException("Digit <= 0:" + digit);
        }
        if (digit.equals(BigInteger.ONE)) {
            return BigInteger.ONE;
        }

        BigInteger answer = BigInteger.ONE;
        Map<BigInteger, BigInteger> mapOfPrimeMultipliers = factorizationService.getMapOfAllPrimeMultipliers(digit);
        for (Map.Entry<BigInteger, BigInteger> entry : mapOfPrimeMultipliers.entrySet()) {
            BigInteger multiplier = entry.getKey();
            BigInteger degreeOfMultiplier = entry.getValue();

            BigInteger eulerFunctionValue = countEulerFunctionForPrimeDigit(multiplier, degreeOfMultiplier.intValue());
            answer = answer.multiply(eulerFunctionValue);
        }
        return answer;
    }

    private BigInteger countEulerFunctionForPrimeDigit(BigInteger digit, int exponent) {
        return digit.pow(exponent).subtract(digit.pow(exponent-1));
    }

    private EEATuple EEA(BigInteger a, BigInteger b) {
        if (b.equals(BigInteger.ZERO)) {
            return new EEATuple(a, BigInteger.ONE, BigInteger.ZERO);
        }
        EEATuple eeaTuple = EEA(b, a.mod(b));

        BigInteger d = eeaTuple.d;
        BigInteger x = eeaTuple.x;
        BigInteger y = eeaTuple.y;
        return new EEATuple(d, y, x.subtract(y.multiply(a.divide(b))));
    }

    private BigInteger pow(BigInteger base, BigInteger exponent) {
        BigInteger result = BigInteger.ONE;
        while (exponent.signum() > 0) {
            if (exponent.testBit(0)) result = result.multiply(base);
            base = base.multiply(base);
            exponent = exponent.shiftRight(1);
        }
        return result;
    }
}
