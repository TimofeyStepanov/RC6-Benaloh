package com.company.crypto.benaloh.algebra.discreteLogarithm;

import java.math.BigInteger;

public interface DiscreteLogarithmService {
    BigInteger getDiscreteLogarithm(BigInteger base, BigInteger arg, BigInteger modulo);
}
