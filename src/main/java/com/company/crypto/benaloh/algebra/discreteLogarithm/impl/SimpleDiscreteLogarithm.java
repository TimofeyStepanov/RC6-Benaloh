package com.company.crypto.benaloh.algebra.discreteLogarithm.impl;

import com.company.crypto.benaloh.algebra.discreteLogarithm.DiscreteLogarithmService;
import lombok.extern.slf4j.Slf4j;

import java.math.BigInteger;

@Deprecated
@Slf4j
public class SimpleDiscreteLogarithm implements DiscreteLogarithmService {
    public BigInteger getDiscreteLogarithm(BigInteger base, BigInteger arg, BigInteger modulo) {
        log.info("base:" + base);
        log.info("arg:" + arg);
        log.info("modulo:" + modulo);


        BigInteger m = BigInteger.ZERO;
        while (true) {
            BigInteger toCheck = base.modPow(m, modulo);
            if (toCheck.equals(arg)) {
                log.info("i:" + m);
                return m;
            }
            m = m.add(BigInteger.ONE);
        }
    }
}
