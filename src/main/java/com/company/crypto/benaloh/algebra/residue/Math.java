package com.company.crypto.benaloh.algebra.residue;


import com.company.crypto.benaloh.algebra.prime.PrimeChecker;
import com.company.crypto.benaloh.algebra.prime.PrimeCheckerFabric;
import com.company.crypto.benaloh.algebra.prime.PrimeCheckerType;

import java.math.BigInteger;
import java.util.*;

public final class Math {
    private final PollardRho pollardRho = new PollardRho(PrimeCheckerType.MILLER_RABIN);

    public int getLegendreSymbol(BigInteger a, BigInteger p) {
        return countJacobiSymbol(a, p);
    }
    public int getJacobiSymbol(BigInteger a, BigInteger p) {
        return countJacobiSymbol(a, p);
    }

    private int countJacobiSymbol(BigInteger a, BigInteger p) {
        return recursionCountJacobiSymbol(a, p).intValue();
    }

    private BigInteger recursionCountJacobiSymbol(BigInteger a, BigInteger p) {
        if (a.equals(BigInteger.ONE)) {
            return BigInteger.ONE;
        }
        if (a.mod(p).equals(BigInteger.ZERO)) {
            return BigInteger.ZERO;
        }

        BigInteger answer;
        if (a.compareTo(BigInteger.ZERO) < 0) {
            answer = recursionCountJacobiSymbol(a.negate(), p);

            BigInteger degree = p.subtract(BigInteger.ONE).divide(BigInteger.TWO);
            if (powMinusOne(degree) == -1) {
                answer = answer.negate();
            }
            return answer;
        } else if (isEven(a)) {
            answer = recursionCountJacobiSymbol(a.divide(BigInteger.TWO), p);

            BigInteger degree = p.pow(2).subtract(BigInteger.ONE).divide(BigInteger.valueOf(8));
            if (powMinusOne(degree) == -1) {
                answer = answer.negate();
            }
            return answer;
        } else if (a.compareTo(p) < 0) {
            BigInteger degree = a.subtract(BigInteger.ONE).divide(BigInteger.TWO)
                    .multiply(p.subtract(BigInteger.ONE).divide(BigInteger.TWO));

            answer = recursionCountJacobiSymbol(p, a);


            if (powMinusOne(degree) == -1) {
                answer = answer.negate();
            }
            return answer;
        } else {
            return recursionCountJacobiSymbol(a.mod(p), p);
        }

    }

    private boolean isEven(BigInteger digit) {
        BigInteger mod = digit.mod(BigInteger.TWO);
        return mod.equals(BigInteger.ZERO);
    }

    private int powMinusOne(BigInteger degree) {
        if (degree.equals(BigInteger.ZERO)) {
            return 1;
        }

        BigInteger mod = degree.mod(BigInteger.TWO);
        return mod.equals(BigInteger.ZERO) ? 1 : -1;
    }


    public List<BigInteger> getDigitFactorization(BigInteger digit) {
        return pollardRho.getFactorList(digit);
    }

    public Set<BigInteger> getPrimeMultipliersOfDigit(BigInteger digit) {
        return pollardRho.getFactorSet(digit);
    }

    private static class PollardRho {
        private static final double PRECISION = 0.99999999999999;
        private final PrimeChecker primeChecker;

        public PollardRho(PrimeCheckerType type) {
            this.primeChecker = PrimeCheckerFabric.getInstance(type);
        }

        public Set<BigInteger> getFactorSet(BigInteger digit) {
            if (digit.equals(BigInteger.ONE)) {
                return new HashSet<>();
            }

            Set<BigInteger> factors = new HashSet<>();
            recursionFactor(digit, factors);
            return factors;
        }

        public List<BigInteger> getFactorList(BigInteger digit) {
            if (digit.equals(BigInteger.ONE)) {
                return new ArrayList<>();
            }

            List<BigInteger> factors = new ArrayList<>();
            recursionFactor(digit, factors);
            return factors;
        }

        private void recursionFactor(BigInteger digit, Collection<BigInteger> factors) {
            do {
                if (primeChecker.isPrime(digit, PRECISION)) {
                    factors.add(digit);
                    return;
                }
                BigInteger divisor = getDivisor(digit);
                factors.add(divisor);
                digit = digit.divide(divisor);
            } while (!digit.equals(BigInteger.ONE));
            //recursionFactor(divisor, factors);
            //recursionFactor(digit.divide(divisor), factors);
        }

        private BigInteger getDivisor(BigInteger digit) {
            if (digit.mod(BigInteger.TWO).equals(BigInteger.ZERO)) {
                return BigInteger.TWO;
            }

            // 103291123123123
            // 1271452995501029494595481059
            // 22222222222222222222222222222222222

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
    }
}
