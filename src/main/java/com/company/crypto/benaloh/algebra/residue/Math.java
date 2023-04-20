package com.company.crypto.benaloh.algebra.residue;


import java.math.BigInteger;

public final class Math {
    public int getLegendreSymbol(BigInteger a, BigInteger p) {
        return countJacobiSymbol(a, p);
    }
    public int getJacobiSymbol(BigInteger a, BigInteger p) {
        return countJacobiSymbol(a, p);
    }

    private int countJacobiSymbol(BigInteger a, BigInteger p) {
        return recursionCountJacobiSymbol(a, p).intValue();
    }

    private BigInteger recursionCountJacobiSymbol(BigInteger a, BigInteger p) {
        if (a.equals(BigInteger.ONE)) {
            return BigInteger.ONE;
        }
        if (a.mod(p).equals(BigInteger.ZERO)) {
            return BigInteger.ZERO;
        }

        BigInteger answer;
        if (a.compareTo(BigInteger.ZERO) < 0) {
            answer = recursionCountJacobiSymbol(a.negate(), p);

            BigInteger degree = p.subtract(BigInteger.ONE).divide(BigInteger.TWO);
            if (powMinusOne(degree) == -1) {
                answer = answer.negate();
            }
            return answer;
        } else if (isEven(a)) {
            answer = recursionCountJacobiSymbol(a.divide(BigInteger.TWO), p);

            BigInteger degree = p.pow(2).subtract(BigInteger.ONE).divide(BigInteger.valueOf(8));
            if (powMinusOne(degree) == -1) {
                answer = answer.negate();
            }
            return answer;
        } else if (a.compareTo(p) < 0) {
            BigInteger degree = a.subtract(BigInteger.ONE).divide(BigInteger.TWO)
                    .multiply(p.subtract(BigInteger.ONE).divide(BigInteger.TWO));

            answer = recursionCountJacobiSymbol(p, a);


            if (powMinusOne(degree) == -1) {
                answer = answer.negate();
            }
            return answer;
        } else {
            return recursionCountJacobiSymbol(a.mod(p), p);
        }

    }

    private boolean isEven(BigInteger digit) {
        BigInteger mod = digit.mod(BigInteger.TWO);
        return mod.equals(BigInteger.ZERO);
    }

    private int powMinusOne(BigInteger degree) {
        if (degree.equals(BigInteger.ZERO)) {
            return 1;
        }

        BigInteger mod = degree.mod(BigInteger.TWO);
        return mod.equals(BigInteger.ZERO) ? 1 : -1;
    }
}
