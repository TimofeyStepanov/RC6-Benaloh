package com.company.cripto.aesImpl.round.impl;

import com.company.cripto.aesImpl.algorithm.impl.RC6;
import com.company.cripto.aesImpl.round.RoundKeysGenerator;
import com.google.common.primitives.Longs;
import lombok.Data;

import java.math.BigDecimal;

@Data
public final class RoundKeysGeneratorRC6 implements RoundKeysGenerator {
    private final int wordLength;
    private final int roundNumber;
    private final int cipherKeyLength;

    public RoundKeysGeneratorRC6(int wordLength, int roundNumber, RC6.CipherKeyLength cipherKeyLength) {
        this.wordLength = wordLength;
        this.roundNumber = roundNumber;
        this.cipherKeyLength = cipherKeyLength.bitsNumber;
    }

    @Override
    public long[] generate(byte[] cipherKey) {
        if (cipherKey.length != cipherKeyLength / Byte.SIZE) {
            throw new IllegalArgumentException(String.format(
                    "Wrong length of cipher key! Required %d, provided %d",
                    cipherKeyLength / Byte.SIZE,
                    cipherKey.length
            ));
        }

        long[] s = new long[2 * roundNumber + 4];
        s[0] = getP();
        long q = getQ();
        for (int i = 1; i < s.length; i++) {
            s[i] = s[i - 1] + q;
        }

        long[] words = translateByteArrayToWordArray(cipherKey);

        int iterationNumber = 3 * Math.max(words.length, 2 * roundNumber + 4);
        int i = 0;
        int j = 0;

        long a = 0;
        long b = 0;
        for (int k = 1; k < iterationNumber; k++) {
            a = s[i] = leftCycleShift(s[i] + a + b, 3);
            b = words[j] = leftCycleShift(words[j] + a + b, a + b);

            i = (i + 1) % (2 * roundNumber + 4);
            j = (j + 1) % words.length;
        }
        return s;
    }

    private long getP() {
        BigDecimal twoDegree = BigDecimal.valueOf(2L << wordLength);
        return getUnevenDigit(twoDegree.multiply(BigDecimal.valueOf(Math.E - 2)));
    }

    private long getUnevenDigit(BigDecimal p) {
        long longP = p.longValue();
        return (longP & 1) != 0 ? longP : longP + 1;
    }

    private long getQ() {
        final double f = 1.6180339887498948482;
        BigDecimal twoDegree = BigDecimal.valueOf(2L << wordLength);
        return getUnevenDigit(twoDegree.multiply(BigDecimal.valueOf(f - 1)));
    }

    private long[] translateByteArrayToWordArray(byte[] cipherKey) {
        long[] words = new long[cipherKey.length * Byte.SIZE / wordLength];

        int wordLengthInByte = wordLength / Byte.SIZE;
        byte[] word = new byte[wordLengthInByte];

        int i = 0;
        int j = 0;
        while (i < cipherKey.length) {
            System.arraycopy(cipherKey, i, word, 0, wordLengthInByte);
            words[j] = Longs.fromByteArray(word);

            j++;
            i += wordLengthInByte;
        }
        return words;
    }

    private long leftCycleShift(long digit, long shift) {
        return (digit << shift) | (digit >> (Long.SIZE - shift));
    }
}
