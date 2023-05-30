package com.company.crypto.benaloh.algebra.discreteLogarithm.impl;

import com.company.crypto.benaloh.algebra.discreteLogarithm.DiscreteLogarithmService;
import lombok.RequiredArgsConstructor;

import java.math.BigInteger;


@RequiredArgsConstructor
public class SimpleDiscreteLogarithm implements DiscreteLogarithmService {
    private final BigInteger r;

    public BigInteger getDiscreteLogarithm(BigInteger base, BigInteger arg, BigInteger modulo) {
        BigInteger m = BigInteger.ZERO;
        while (m.compareTo(r) <= 0) {
            BigInteger toCheck = base.modPow(m, modulo);
            if (toCheck.equals(arg)) {
                return m;
            }
            m = m.add(BigInteger.ONE);
        }
        throw new IllegalArgumentException("Can't find logarithm.");
    }
}
