package com.company.crypto.benaloh.algebra.factorization;

import java.math.BigInteger;
import java.util.List;
import java.util.Set;

public interface FactorizationService {
   List<BigInteger> getAllPrimeMultipliers(BigInteger digit);
   Set<BigInteger> getUniquePrimeMultipliers(BigInteger digit);
}
