package com.company.crypto.aesImpl.mode.impl;

import com.company.crypto.aesImpl.algorithm.SymmetricalBlockEncryptionAlgorithm;

public class RDCypher extends CTRCypher {
    public RDCypher(SymmetricalBlockEncryptionAlgorithm algorithm, byte[] initialVector) {
        super(algorithm, 0);

        this.delta = initialVector[initialVector.length-1];
        super.startDigit = translateArrayIntoLong(initialVector);
    }
    private long translateArrayIntoLong(byte[] array) {
        long value = 0;
        for (byte b : array) {
            value = (value << Byte.SIZE) + (b & 0xFF);
        }
        return value;
    }
}
