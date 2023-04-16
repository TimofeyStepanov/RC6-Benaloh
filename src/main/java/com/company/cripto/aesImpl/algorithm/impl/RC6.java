package com.company.cripto.aesImpl.algorithm.impl;

import com.company.cripto.aesImpl.algorithm.SymmetricalBlockEncryptionAlgorithm;

public class RC6 implements SymmetricalBlockEncryptionAlgorithm {
    public enum CipherKeyLength {
        BIT_128(128), BIT_192(192), BIT_256(256);

        public final int bitsNumber;

        CipherKeyLength(int bitsNumber) {
            this.bitsNumber = bitsNumber;
        }
    }

    @Override
    public byte[] decode(byte[] inputBlock) {
        return new byte[0];
    }

    @Override
    public byte[] encode(byte[] inputBlock) {
        return new byte[0];
    }

    @Override
    public void setKey(byte[] cipherKey) {

    }

    @Override
    public int getOpenTextBlockSizeInBytes() {
        return 0;
    }
}
