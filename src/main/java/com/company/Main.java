package com.company;

import com.company.crypto.benaloh.algebra.prime.PrimeChecker;
import com.company.crypto.benaloh.algebra.prime.PrimeCheckerFabric;
import com.company.crypto.benaloh.algebra.prime.PrimeCheckerType;

import java.math.BigInteger;
import java.util.*;

public class Main {

    public static class PollardRho {
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
            return digit.pow(2).add(BigInteger.ONE);
        }
    }


    public static void main(String[] args) {
        // 28897710696848861219331411561214669316038653
        Scanner scanner = new Scanner(System.in);
        System.out.println("Pollard Rho Algorithm\n");
        System.out.println("Enter a number");

        String digit = scanner.nextLine();
        System.out.println("\nFactors are : ");

        PollardRho pollardRho = new PollardRho(PrimeCheckerType.MILLER_RABIN);
        Collection<BigInteger> collection = pollardRho.getFactorList(new BigInteger(digit));
        collection.forEach(System.out::println);

        BigInteger ans = BigInteger.ONE;
        for (BigInteger el : collection) {
            ans = ans.multiply(el);
        }
        System.out.println(ans);
    }
}
