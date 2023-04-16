package com.company.cripto.aesImpl.round.impl;

import com.company.cripto.aesImpl.algorithm.impl.RC6;
import com.company.cripto.aesImpl.round.RoundKeysGenerator;

import java.math.BigDecimal;
import java.math.BigInteger;

public final class RoundKeysGeneratorImpl implements RoundKeysGenerator {
    private final BigInteger[] s;

    private final int wordLength;
    private final int roundNumber;
    private final int cipherKeyLength;

    public RoundKeysGeneratorImpl(int wordLength, int roundNumber, RC6.CipherKeyLength cipherKeyLength) {
        this.wordLength = wordLength;
        this.roundNumber = roundNumber;
        this.cipherKeyLength = cipherKeyLength.bitsNumber;

        BigInteger q = getQ();

        s = new BigInteger[2 * roundNumber + 3];
        s[0] = getP();
        for (int i = 1; i < s.length; i++) {
            s[i] = s[i - 1].add(q);
        }
    }

    private BigInteger getP() {
        BigDecimal eMinusTwo = BigDecimal.valueOf(Math.E - 2);
        BigDecimal twoDegree = (BigDecimal.valueOf(2)).pow(wordLength);
        return getUnevenDigit(eMinusTwo.multiply(twoDegree));
    }

    private BigInteger getUnevenDigit(BigDecimal digit) {
        BigInteger bigInteger = digit.toBigInteger();
        boolean digitIsUneven = bigInteger.mod(BigInteger.TWO).equals(BigInteger.ONE);
        return digitIsUneven ? bigInteger : bigInteger.add(BigInteger.ONE);
    }

    private BigInteger getQ() {
        final double f = 1.6180339887498948482;
        BigDecimal fMinusOne = BigDecimal.valueOf(f - 1);
        BigDecimal twoDegree = (BigDecimal.valueOf(2)).pow(wordLength);
        return getUnevenDigit(fMinusOne.multiply(twoDegree));
    }


    @Override
    public byte[][] generate(byte[] cipherKey) {
        if (cipherKey.length != cipherKeyLength / Byte.SIZE) {
            throw new IllegalArgumentException(String.format(
                    "Wrong length of cipher key! Required %d, provided %d",
                    cipherKeyLength / Byte.SIZE,
                    cipherKey.length
            ));
        }

        BigInteger[] words = translateByteArrayToWordArray(cipherKey);

        int iterationNumber = 3 * Math.max(words.length, 2 * roundNumber + 4);
        int i = 0;
        int j = 0;

        BigInteger a = BigInteger.ZERO;
        BigInteger b = BigInteger.ZERO;
        for (int k = 1; k < iterationNumber; k++) {
            a = s[i] = leftCycleShift(s[i].add(a).add(b), 3);
            b = words[j] = leftCycleShift(words[j].add(a).add(b), a.add(b));

            i = (i + 1) % (2 * roundNumber + 4);
            j = (j + 1) % words.length;
        }
        return new byte[0][0];
    }

    private BigInteger[] translateByteArrayToWordArray(byte[] cipherKey) {
        BigInteger[] words = new BigInteger[cipherKey.length * Byte.SIZE / wordLength];

        int wordLengthInByte = wordLength / Byte.SIZE;
        byte[] word = new byte[wordLengthInByte];

        int i = 0;
        int j = 0;
        while (i < cipherKey.length) {
            System.arraycopy(cipherKey, i, word, 0, wordLengthInByte);
            reverseArray(word);
            words[j] = new BigInteger(word);

            j++;
            i += wordLengthInByte;
        }
        return words;
    }

    private void reverseArray(byte[] array) {
        for (int i = 0; i < array.length; i++) {
            byte tmp = array[i];
            array[i] = array[array.length - 1 - i];
            array[array.length - 1 - i] = tmp;
        }
    }

    private BigInteger leftCycleShift(BigInteger digit, int shift) {
        return digit.shiftLeft(shift)
                .or(digit.shiftRight(digit.bitLength() - shift));
    }

    private BigInteger leftCycleShift(BigInteger digit, BigInteger shift) {
        int shiftInt = shift.mod(BigInteger.valueOf(digit.bitLength())).intValue();
        return digit.shiftLeft(shiftInt)
                .or(digit.shiftRight(digit.bitLength() - shiftInt));
    }
}
