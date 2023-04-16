package com.company.cripto.aesImpl.mode.impl;

import com.company.cripto.aesImpl.algorithm.SymmetricalBlockEncryptionAlgorithm;
import com.company.cripto.aesImpl.mode.SymmetricalBlockModeCypher;
import com.company.cripto.aesImpl.padding.PKCS7;

import java.io.*;

public class RDPlusHCypher extends SymmetricalBlockModeCypher {
    private final long startDigit;
    private final int delta;
    private final byte[] hash;

    public RDPlusHCypher(SymmetricalBlockEncryptionAlgorithm algorithm, byte[] initialVector, byte[] hash) {
        super(algorithm, Runtime.getRuntime().availableProcessors()-1);

        this.delta = initialVector[initialVector.length-1];
        this.startDigit = translateArrayIntoLong(initialVector);
        this.hash = hash;
    }
    private long translateArrayIntoLong(byte[] array) {
        long value = 0;
        for (byte b : array) {
            value = (value << Byte.SIZE) + (b & 0xFF);
        }
        return value;
    }

    @Override
    public void encode(File inputFile, File outputFile) throws IOException {
        try (
                InputStream inputStream = new BufferedInputStream(new FileInputStream(inputFile));
                OutputStream outputStream = new BufferedOutputStream(new FileOutputStream(outputFile));
        ) {
            long i = 0;
            long read;

            byte[] previousOpenBlock = new byte[bufferSize];
            System.arraycopy(hash, 0, previousOpenBlock, 0, bufferSize);

            byte[] presentedDigit = new byte[bufferSize];
            while ((read = inputStream.read(buffer, 0, bufferSize)) != -1) {
                if (read < bufferSize) {
                    PKCS7.doPadding(buffer, (int) (bufferSize - read));
                }

                presentLongAsByteArray(presentedDigit, i);
                byte[] encoded = algorithm.encode(presentedDigit);

                xor(buffer, encoded);
                xor(buffer, previousOpenBlock);
                outputStream.write(buffer);

                i += delta;
            }
        }
    }

    @Override
    public void decode(File inputFile, File outputFile) throws IOException {
        try (
                InputStream inputStream = new BufferedInputStream(new FileInputStream(inputFile));
                OutputStream outputStream = new BufferedOutputStream(new FileOutputStream(outputFile));
        ) {
            long i = startDigit;
            boolean isFirstDecode = true;
            byte[] encoded = null;

            byte[] previousOpenBlock = new byte[bufferSize];
            System.arraycopy(hash, 0, previousOpenBlock, 0, bufferSize);

            byte[] presentedDigit = new byte[bufferSize];
            while (inputStream.read(buffer, 0, bufferSize) != -1) {
                if (isFirstDecode) {
                    isFirstDecode = false;
                } else {
                    outputStream.write(encoded);
                    System.arraycopy(encoded, 0, previousOpenBlock, 0, bufferSize);

                    i += delta;
                }

                presentLongAsByteArray(presentedDigit, i);
                encoded = algorithm.encode(presentedDigit);
                xor(encoded, buffer);
                xor(encoded, previousOpenBlock);
            }
            if (!isFirstDecode) {
                int position = PKCS7.getPositionOfFinishByte(encoded);
                outputStream.write(encoded, 0, position);
            }
        }
    }
}
