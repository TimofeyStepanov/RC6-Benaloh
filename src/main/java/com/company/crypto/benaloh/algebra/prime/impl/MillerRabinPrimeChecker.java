package com.company.crypto.benaloh.algebra.prime.impl;

import com.company.crypto.benaloh.algebra.prime.PrimeChecker;

import java.math.BigInteger;

public class MillerRabinPrimeChecker extends PrimeChecker {
    @Override
    protected boolean isNotPrime(BigInteger digitToCheck, double precision) {
        long s = 0;
        BigInteger t = digitToCheck.subtract(BigInteger.ONE);
        while (t.mod(BigInteger.TWO).equals(BigInteger.ZERO)) {
            t = t.divide(BigInteger.TWO);
            s++;
        }

        BigInteger randomDigit = super.getPositiveRandomDigit(BigInteger.TWO, digitToCheck.subtract(BigInteger.TWO));
        BigInteger x = randomDigit.modPow(t, digitToCheck);
        if (x.equals(BigInteger.ONE) || x.equals(digitToCheck.subtract(BigInteger.ONE))) {
            return false;
        }

        for (long i = 0; i < s-1; i++) {
            x = x.modPow(BigInteger.TWO, digitToCheck);
            if (x.equals(BigInteger.ONE)) {
                return true;
            }
            if (x.equals(digitToCheck.subtract(BigInteger.ONE))) {
                break;
            }
        }
        return !x.equals(digitToCheck.subtract(BigInteger.ONE));
    }
}
