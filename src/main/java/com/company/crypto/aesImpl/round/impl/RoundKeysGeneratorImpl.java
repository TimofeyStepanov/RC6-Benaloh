package com.company.crypto.aesImpl.round.impl;

import com.company.crypto.aesImpl.algorithm.impl.RC6Bits32;
import com.company.crypto.aesImpl.round.RoundKeysGenerator32BitsRC6;
import lombok.Data;

import java.math.BigDecimal;

@Data
public final class RoundKeysGeneratorImpl implements RoundKeysGenerator32BitsRC6 {
    private final int wordLength;
    private final int roundNumber;
    private final int cipherKeyLength;

    public RoundKeysGeneratorImpl(int wordLength, int roundNumber, RC6Bits32.CipherKeyLength cipherKeyLength) {
        this.wordLength = wordLength;
        this.roundNumber = roundNumber;
        this.cipherKeyLength = cipherKeyLength.bitsNumber;
    }

    @Override
    public int[] generate(byte[] cipherKey) {
        if (cipherKey.length != cipherKeyLength / Byte.SIZE) {
            throw new IllegalArgumentException(String.format(
                    "Wrong length of cipher key! Required %d, provided %d",
                    cipherKeyLength / Byte.SIZE,
                    cipherKey.length
            ));
        }

        int[] s = new int[2 * roundNumber + 4];
        s[0] = getP();
        int q = getQ();
        for (int i = 1; i < s.length; i++) {
            s[i] = s[i - 1] + q;
        }

        int[] words = translateByteArrayToWordArray(cipherKey);

        int iterationNumber = 3 * Math.max(words.length, s.length);
        int i = 0;
        int j = 0;

        int a = 0;
        int b = 0;
        for (int k = 0; k < iterationNumber; k++) {
            a = s[i] = leftCycleShift(s[i] + a + b, 3);
            b = words[j] = leftCycleShift(words[j] + a + b, a + b);

            i = (i + 1) % s.length;
            j = (j + 1) % words.length;
        }
        return s;
    }

    private int getP() {
        BigDecimal twoDegree = BigDecimal.valueOf(1L << wordLength);
        return getUnevenDigit(twoDegree.multiply(BigDecimal.valueOf(Math.E - 2)));
    }

    private int getUnevenDigit(BigDecimal p) {
        long longP = p.longValue();
        return (int) ((longP & 1) != 0 ? longP : longP + 1);
    }

    private int getQ() {
        final double f = 1.6180339887498948482;
        BigDecimal twoDegree = BigDecimal.valueOf(1L << wordLength);
        return getUnevenDigit(twoDegree.multiply(BigDecimal.valueOf(f - 1)));
    }

    private int[] translateByteArrayToWordArray(byte[] cipherKey) {
        int[] translatedArray = new int[cipherKeyLength / wordLength];
        int index = 0;
        for(int i = 0; i < translatedArray.length; i++) {
            translatedArray[i] = (cipherKey[index++] & 0xFF)
                    | ((cipherKey[index++] & 0xFF) << Byte.SIZE)
                    | ((cipherKey[index++] & 0xFF) << Byte.SIZE * 2)
                    | ((cipherKey[index++] & 0xFF) << Byte.SIZE * 3);
        }
        return translatedArray;
    }

    private int leftCycleShift(int digit, int shift) {
        return (digit << shift) | (digit >> (wordLength - shift));
    }
}
