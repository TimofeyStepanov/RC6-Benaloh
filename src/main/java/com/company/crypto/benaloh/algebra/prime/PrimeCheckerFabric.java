package com.company.crypto.benaloh.algebra.prime;

import com.company.crypto.benaloh.algebra.prime.impl.FermatPrimeChecker;
import com.company.crypto.benaloh.algebra.prime.impl.MillerRabinPrimeChecker;
import com.company.crypto.benaloh.algebra.prime.impl.SolovayStrassenPrimeChecker;
import com.company.crypto.benaloh.algebra.residue.Math;

import java.util.Map;

public final class PrimeCheckerFabric {
    private static final Map<PrimeCheckerType, PrimeChecker> typeAndInstance = Map.of(
            PrimeCheckerType.FERMAT, new FermatPrimeChecker(),
            PrimeCheckerType.MILLER_RABIN, new MillerRabinPrimeChecker(),
            PrimeCheckerType.SOLOVEY_STRASSEN, new SolovayStrassenPrimeChecker(new Math())
    );

    public static PrimeChecker getInstance(PrimeCheckerType type) {
        return typeAndInstance.get(type).clone();
    }

    private PrimeCheckerFabric() {

    }
}
