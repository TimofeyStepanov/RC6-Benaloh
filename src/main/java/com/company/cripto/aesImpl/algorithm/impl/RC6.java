package com.company.cripto.aesImpl.algorithm.impl;

import com.company.cripto.aesImpl.algorithm.SymmetricalBlockEncryptionAlgorithm;
import com.company.cripto.aesImpl.round.RoundKeysGenerator;
import com.company.cripto.aesImpl.round.impl.RoundKeysGeneratorRC6;
import com.google.common.primitives.Ints;

import java.util.Arrays;
import java.util.Objects;


public class RC6 implements SymmetricalBlockEncryptionAlgorithm {
    private static final int OPEN_TEXT_BLOCK_LENGTH = 128;
    private static final int ROUND_NUMBER = 20;

    public enum CipherKeyLength {
        BIT_128(128), BIT_192(192), BIT_256(256);
        public final int bitsNumber;

        CipherKeyLength(int bitsNumber) {
            this.bitsNumber = bitsNumber;
        }
    }

    public static RC6 getInstance(RoundKeysGenerator roundKeysGenerator) {
        if (!(roundKeysGenerator instanceof RoundKeysGeneratorRC6)) {
            throw new IllegalArgumentException("Wrong key generator!");
        }
        if (((RoundKeysGeneratorRC6) roundKeysGenerator).getRoundNumber() != ROUND_NUMBER) {
            throw new IllegalStateException("Wrong round number!");
        }
        return new RC6(roundKeysGenerator);
    }

    private byte[] cipherKey;
    private final int wordLength;
    private final RoundKeysGenerator roundKeysGenerator;

    private RC6(RoundKeysGenerator roundKeysGenerator) {
        this.roundKeysGenerator = roundKeysGenerator;
        this.wordLength = ((RoundKeysGeneratorRC6) roundKeysGenerator).getWordLength();
    }

    @Override
    public byte[] encode(byte[] inputBlock) {
        checkArgs(inputBlock);

        int[] translatedInputArray = translateInputByteArrayIntArray(inputBlock);
        int a = translatedInputArray[0], b = translatedInputArray[1];
        int c = translatedInputArray[2], d = translatedInputArray[3];

        int[] roundKeys = roundKeysGenerator.generate(cipherKey);
        b = b + roundKeys[0];
        d = d + roundKeys[1];
        for (int i = 1; i <= ROUND_NUMBER; i++) {
            int t = leftCycleShift(b * (2 * b + 1), (int) log2(wordLength));
            int u = leftCycleShift(d * (2 * d + 1), (int) log2(wordLength));
            a = leftCycleShift(a ^ t, u) + roundKeys[2 * i];
            c = leftCycleShift(c ^ u, t) + roundKeys[2 * i + 1];

            int tmpA = a;
            a = b;
            b = c;
            c = d;
            d = tmpA;
        }
        a = a + roundKeys[2 * ROUND_NUMBER + 2];
        c = c + roundKeys[2 * ROUND_NUMBER + 3];

        translatedInputArray[0] = a;
        translatedInputArray[1] = b;
        translatedInputArray[2] = c;
        translatedInputArray[3] = d;

        translateIntArrayToByteArray(translatedInputArray, inputBlock);
        return inputBlock;
    }

    private void checkArgs(byte[] inputBlock) {
        Objects.requireNonNull(inputBlock);
        Objects.requireNonNull(cipherKey);

        if (inputBlock.length != OPEN_TEXT_BLOCK_LENGTH / Byte.SIZE) {
            throw new IllegalArgumentException("Wrong size of input block to encode!");
        }
    }

    int[] translateInputByteArrayIntArray(byte[] array) {
//        int[] translatedArray = new int[OPEN_TEXT_BLOCK_LENGTH / wordLength];
//        int wordLengthInBytes = wordLength / Byte.SIZE;
//        for (int i = 0; i < translatedArray.length; i++) {
//            int currentByte = i * wordLength / Byte.SIZE;
//            translatedArray[i] = Ints.fromByteArray(Arrays.copyOfRange(array, currentByte, currentByte + wordLengthInBytes));
//        }
//        return translatedArray;

        int[] translated = new int[OPEN_TEXT_BLOCK_LENGTH / wordLength];
        int index = 0;
        for(int i=0; i < translated.length; i++) {
            translated[i] = (array[index++] & 0xFF)
                    | ((array[index++] & 0xFF) << 8)
                    | ((array[index++] & 0xFF) << 16)
                    | ((array[index++] & 0xFF) << 24);
        }
        return translated;
    }

    private int leftCycleShift(int digit, int shift) {
        return (digit << shift) | (digit >>> (wordLength - shift));
    }

     void translateIntArrayToByteArray(int[] src, byte[] dest) {
        for(int i = 0;i < dest.length;i++){
            dest[i] = (byte)((src[i/4] >>> (i % 4)*8) & 0xff);
        }
//        int outputArrayPtr = 0;
//        for (int longDigit : src) {
//            byte[] translatedLongDigit = Ints.toByteArray(longDigit);
//            for (byte translatedByte : translatedLongDigit) {
//                dest[outputArrayPtr++] = translatedByte;
//            }
//        }
    }

    private double log2(double digit) {
        return Math.log(digit) / Math.log(2);
    }

    @Override
    public byte[] decode(byte[] inputBlock) {
        checkArgs(inputBlock);

        int[] translatedInputArray = translateInputByteArrayIntArray(inputBlock);
        int a = translatedInputArray[0], b = translatedInputArray[1];
        int c = translatedInputArray[2], d = translatedInputArray[3];

        int[] roundKeys = roundKeysGenerator.generate(cipherKey);
        c = c - roundKeys[2 * ROUND_NUMBER + 3];
        a = a - roundKeys[2 * ROUND_NUMBER + 2];
        for (int i = ROUND_NUMBER; i >= 1; i--) {
            int tmpD = d;
            d = c;
            c = b;
            b = a;
            a = tmpD;

            int u = leftCycleShift(d * (2 * d + 1), (int) log2(wordLength));
            int t = leftCycleShift(b * (2 * b + 1), (int) log2(wordLength));

            c = rightCycleShift(c - roundKeys[2 * i + 1], t) ^ u;
            a = rightCycleShift(a - roundKeys[2 * i], u) ^ t;
        }
        d = d - roundKeys[1];
        b = b - roundKeys[0];

        translatedInputArray[0] = a;
        translatedInputArray[1] = b;
        translatedInputArray[2] = c;
        translatedInputArray[3] = d;

        translateIntArrayToByteArray(translatedInputArray, inputBlock);
        return inputBlock;
    }

    private int rightCycleShift(int digit, int shift) {
        return (digit >>> shift) | (digit << (wordLength - shift));
    }

    @Override
    public void setKey(byte[] cipherKey) {
        this.cipherKey = cipherKey;
    }

    @Override
    public int getOpenTextBlockSizeInBytes() {
        return OPEN_TEXT_BLOCK_LENGTH;
    }
}
