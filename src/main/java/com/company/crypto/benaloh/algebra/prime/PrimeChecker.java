package com.company.crypto.benaloh.algebra.prime;

import java.math.BigInteger;
import java.util.Random;

public abstract class PrimeChecker implements Cloneable {
    private final Random random = new Random();

    public boolean isPrime(BigInteger digitToCheck, double precision) {
        this.checkPrecision(precision);
        this.checkDigit(digitToCheck);

        if (digitToCheck.equals(BigInteger.TWO) || digitToCheck.equals(BigInteger.valueOf(3))) {
            return true;
        }

        int n = this.getIterationNumber(precision);
        for (int i = 0; i < n; i++) {
            if (isNotPrime(digitToCheck, precision)) {
                return false;
            }
        }
        return true;
    }

    protected abstract boolean isNotPrime(BigInteger digitToCheck, double precision);

    protected int getIterationNumber(double precision) {
        int iterationNumber = -log2(1 - precision);
        return Math.max(iterationNumber, 1);
    }

    private int log2(double n) {
        return (int) (Math.log(n) / Math.log(2));
    }


    protected BigInteger getPositiveRandomDigit(BigInteger minDigit, BigInteger maxDigit) {
        BigInteger randomDigit = new BigInteger(maxDigit.bitLength(), random);
        while (randomDigit.compareTo(minDigit) < 0 || randomDigit.compareTo(maxDigit) > 0) {
            randomDigit = new BigInteger(maxDigit.bitLength(), random);
        }
        return randomDigit;
    }


    protected void checkPrecision(double precision) {
        if (precision < 0.5 || precision > 1.0) {
            throw new IllegalArgumentException("Wrong precision");
        }
    }

    protected void checkDigit(BigInteger digitToCheck) {
        if (digitToCheck.compareTo(BigInteger.ONE) < 0) {
            throw new IllegalArgumentException("Wrong digit. Digit < 1. " + digitToCheck);
        }
    }

    protected BigInteger gcd(BigInteger a, BigInteger b) {
        if (a.equals(BigInteger.ZERO)) {
            return b;
        }
        return gcd(b.mod(a), a);
    }

    @Override
    public PrimeChecker clone() {
        try {
            return (PrimeChecker) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalCallerException("Can't do clone");
        }
    }
}
