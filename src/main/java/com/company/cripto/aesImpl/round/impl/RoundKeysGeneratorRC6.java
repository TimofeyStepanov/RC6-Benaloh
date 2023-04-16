package com.company.cripto.aesImpl.round.impl;

import com.company.cripto.aesImpl.algorithm.impl.RC6;
import com.company.cripto.aesImpl.round.RoundKeysGenerator;
import com.google.common.primitives.Ints;
import lombok.Data;

import java.math.BigDecimal;
import java.util.Arrays;

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
        //BigDecimal twoDegree = BigDecimal.valueOf(1L << wordLength);
        //return getUnevenDigit(twoDegree.multiply(BigDecimal.valueOf(Math.E - 2)));
        return 0xb7e15163;
    }

    private int getUnevenDigit(BigDecimal p) {
        //long longP = p.longValue();
        //return (int) ((longP & 1) != 0 ? longP : longP + 1);
        return 0;
    }

    private int getQ() {
//        final double f = 1.6180339887498948482;
//        BigDecimal twoDegree = BigDecimal.valueOf(1L << wordLength);
//        return getUnevenDigit(twoDegree.multiply(BigDecimal.valueOf(f - 1)));
        return 0x9e3779b9;
    }

    private int[] translateByteArrayToWordArray(byte[] cipherKey) {
//        long[] translatedArray = new long[cipherKeyLength / wordLength];
//        int wordLengthInBytes = wordLength / Byte.SIZE;
//        for (int i = 0; i < translatedArray.length; i++) {
//            int currentByte = i * wordLength / Byte.SIZE;
//            translatedArray[i] = Ints.fromByteArray(Arrays.copyOfRange(cipherKey, currentByte, currentByte + wordLengthInBytes));
//        }
//        return translatedArray;

        int[] translated = new int[cipherKeyLength / wordLength];
        int index = 0;
        for(int i=0; i < translated.length; i++) {
            translated[i] = (cipherKey[index++] & 0xFF)| ((cipherKey[index++]& 0xFF)<<8)
                    | ((cipherKey[index++]& 0xFF)<<16)|((cipherKey[index++]& 0xFF)<<24);
        }

        return translated;
    }

    private int leftCycleShift(int digit, int shift) {
        return (digit << shift) | (digit >> (wordLength - shift));
    }
}
