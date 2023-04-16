package com.company.cripto.aesImpl.algorithm.impl;

import com.company.cripto.aesImpl.algorithm.SymmetricalBlockEncryptionAlgorithm;
import com.company.cripto.aesImpl.round.RoundKeysGenerator;
import com.company.cripto.aesImpl.round.RoundTransformer;
import com.company.cripto.aesImpl.round.impl.RoundKeysGeneratorImpl;

import java.math.BigInteger;
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

    private byte[] cipherKey;

    private final RoundKeysGenerator roundKeysGenerator;
    private final RoundTransformer roundTransformer;

    public RC6(RoundKeysGenerator roundKeysGenerator, RoundTransformer roundTransformer) {
        this.roundKeysGenerator = roundKeysGenerator;
        this.roundTransformer = roundTransformer;
    }

    @Override
    public byte[] decode(byte[] inputBlock) {
        Objects.requireNonNull(inputBlock);
        Objects.requireNonNull(cipherKey);

        BigInteger[] roundKeys = roundKeysGenerator.generate(cipherKey);
        for (int i = 0; i < ROUND_NUMBER; i++) {
            BigInteger roundKey = roundKeys[i];
            inputBlock = roundTransformer.decode(inputBlock, roundKey, i == 0);
        }
        return inputBlock;
    }

    @Override
    public byte[] encode(byte[] inputBlock) {
        Objects.requireNonNull(inputBlock);
        Objects.requireNonNull(cipherKey);

        BigInteger[] roundKeys = roundKeysGenerator.generate(cipherKey);
        for (int i = 0; i < ROUND_NUMBER; i++) {
            BigInteger roundKey = roundKeys[i];
            inputBlock = roundTransformer.encode(inputBlock, roundKey, i == ROUND_NUMBER-1);
        }
        return inputBlock;
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
