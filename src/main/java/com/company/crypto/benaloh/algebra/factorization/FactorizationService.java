package com.company.crypto.benaloh.algebra.factorization;

import java.math.BigInteger;
import java.util.List;
import java.util.Map;
import java.util.Set;

public interface FactorizationService {
   List<BigInteger> getListOfAllPrimeMultipliers(BigInteger digit);
   Map<BigInteger, BigInteger> getMapOfAllPrimeMultipliers(BigInteger digit);
   Set<BigInteger> getUniquePrimeMultipliers(BigInteger digit);
}
