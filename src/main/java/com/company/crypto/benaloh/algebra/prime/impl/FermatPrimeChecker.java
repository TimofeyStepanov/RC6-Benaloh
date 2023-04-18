package com.company.crypto.benaloh.algebra.prime.impl;

import com.company.crypto.benaloh.algebra.prime.PrimeChecker;

import java.math.BigInteger;

public class FermatPrimeChecker extends PrimeChecker {
    @Override
    protected boolean isNotPrime(BigInteger digitToCheck, double precision) {
        BigInteger randomDigit = super.getPositiveRandomDigit(BigInteger.TWO, digitToCheck.subtract(BigInteger.TWO));

        BigInteger gcd = super.gcd(digitToCheck, randomDigit);
        if (!gcd.equals(BigInteger.ONE)) {
            return true;
        }

        BigInteger degree = digitToCheck.subtract(BigInteger.ONE);
        BigInteger raisedToADegreeModulo = randomDigit.modPow(degree, digitToCheck);
        return !raisedToADegreeModulo.equals(BigInteger.ONE);
    }


}
