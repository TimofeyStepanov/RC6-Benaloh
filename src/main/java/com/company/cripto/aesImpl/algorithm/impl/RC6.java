package com.company.cripto.aesImpl.algorithm.impl;

import com.company.cripto.aesImpl.algorithm.SymmetricalBlockEncryptionAlgorithm;
import com.company.cripto.aesImpl.round.RoundKeysGenerator;
import com.company.cripto.aesImpl.round.impl.RoundKeysGeneratorRC6;
import com.google.common.primitives.Longs;

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

    public RC6(RoundKeysGenerator roundKeysGenerator) {
        this.roundKeysGenerator = roundKeysGenerator;
        this.wordLength = ((RoundKeysGeneratorRC6) roundKeysGenerator).getWordLength();
    }

    @Override
    public byte[] encode(byte[] inputBlock) {
        checkArgs(inputBlock);

        long[] translatedInputArray = translateInputByteArrayToLongArray(inputBlock, wordLength);
        long a = translatedInputArray[0], b = translatedInputArray[1];
        long c = translatedInputArray[2], d = translatedInputArray[3];

        long[] roundKeys = roundKeysGenerator.generate(cipherKey);
        b = b + roundKeys[0];
        d = d + roundKeys[1];
        for (int i = 1; i < ROUND_NUMBER; i++) {

            long t = leftCycleShift(b * (2 * b + 1), (long) Math.log(wordLength));
            long u = leftCycleShift(d * (2 * d + 1), (long) Math.log(wordLength));
            a = leftCycleShift(a ^ t, u) + roundKeys[2 * i];
            c = leftCycleShift(c ^ u, t) + roundKeys[2 * i + 1];

            long tmpA = a;
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

        translateLongArrayToByteArray(translatedInputArray, inputBlock);
        return inputBlock;
    }

    private void checkArgs(byte[] inputBlock) {
        Objects.requireNonNull(inputBlock);
        Objects.requireNonNull(cipherKey);

        if (inputBlock.length != OPEN_TEXT_BLOCK_LENGTH / Byte.SIZE) {
            throw new IllegalArgumentException("Wrong size of input block to encode!");
        }
    }

    private long[] translateInputByteArrayToLongArray(byte[] array, int wordLength) {
        long[] translatedArray = new long[OPEN_TEXT_BLOCK_LENGTH / wordLength];
        for (int i = 0; i < translatedArray.length; i += wordLength / Byte.SIZE) {
            translatedArray[i] = Longs.fromByteArray(Arrays.copyOfRange(array, i, i + wordLength / Byte.SIZE));
        }
        return translatedArray;
    }

    private long leftCycleShift(long digit, long shift) {
        return (digit << shift) | (digit >> (Long.SIZE - shift));
    }

    private void translateLongArrayToByteArray(long[] src, byte[] dest) {
        int outputArrayPtr = 0;
        for (long longDigit : src) {
            byte[] translatedLongDigit = Longs.toByteArray(longDigit);
            for (byte translatedByte : translatedLongDigit) {
                dest[outputArrayPtr++] = translatedByte;
            }
        }
    }

    @Override
    public byte[] decode(byte[] inputBlock) {
        checkArgs(inputBlock);

        long[] translatedInputArray = translateInputByteArrayToLongArray(inputBlock, wordLength);
        long a = translatedInputArray[0], b = translatedInputArray[1];
        long c = translatedInputArray[2], d = translatedInputArray[3];

        long[] roundKeys = roundKeysGenerator.generate(cipherKey);
        c = c - roundKeys[2 * ROUND_NUMBER + 3];
        a = a - roundKeys[2 * ROUND_NUMBER + 2];
        for (int i = ROUND_NUMBER - 1; i > 0; i--) {
            long tmpA = a;
            a = b;
            b = c;
            c = d;
            d = tmpA;

            long u = leftCycleShift(d * (2 * d + 1), (long) Math.log(wordLength));
            long t = leftCycleShift(b * (2 * b + 1), (long) Math.log(wordLength));
            c = rightCycleShift(c - roundKeys[2 * i + 1], t) ^ u;
            a = rightCycleShift(a - roundKeys[2 * i], u) ^ t;
        }
        d = d - roundKeys[1];
        b = b - roundKeys[0];

        translatedInputArray[0] = a;
        translatedInputArray[1] = b;
        translatedInputArray[2] = c;
        translatedInputArray[3] = d;

        translateLongArrayToByteArray(translatedInputArray, inputBlock);
        return inputBlock;
    }

    private long rightCycleShift(long digit, long shift) {
        return (digit >> shift) | (digit << (Long.SIZE - shift));
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
