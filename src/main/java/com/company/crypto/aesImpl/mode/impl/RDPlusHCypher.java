package com.company.crypto.aesImpl.mode.impl;

import com.company.crypto.aesImpl.CypherInformant;
import com.company.crypto.aesImpl.algorithm.SymmetricalBlockEncryptionAlgorithm;
import com.company.crypto.aesImpl.mode.SymmetricalBlockModeCypher;
import com.company.crypto.aesImpl.padding.PKCS7;

import java.io.*;

public class RDPlusHCypher extends SymmetricalBlockModeCypher {
    private final long startDigit;
    private final int delta;
    private final byte[] hash;

    public RDPlusHCypher(SymmetricalBlockEncryptionAlgorithm algorithm, byte[] initialVector, byte[] hash) {
        super(algorithm,0);

        this.delta = initialVector[initialVector.length-1];
        this.startDigit = translateArrayIntoLong(initialVector);
        this.hash = hash;
    }
    private long translateArrayIntoLong(byte[] array) {
        long value = 0;
        for (byte b : array) {
            value = (value << Byte.SIZE) | (b & 0xFF);
        }
        return value & 0xFF;
    }

    @Override
    public void encode(File inputFile, File outputFile, CypherInformant cypherInformant) throws IOException {
        try (
                InputStream inputStream = new BufferedInputStream(new FileInputStream(inputFile));
                OutputStream outputStream = new BufferedOutputStream(new FileOutputStream(outputFile));
        ) {
            long i = startDigit;
            long read;

            byte[] previousBlock = new byte[bufferSize];
            System.arraycopy(hash, 0, previousBlock, 0, bufferSize);

            byte[] presentedDigit = new byte[bufferSize];
            while ((read = inputStream.read(buffer, 0, bufferSize)) != -1) {
                if (read < bufferSize) {
                    PKCS7.doPadding(buffer, (int) (bufferSize - read));
                }

                presentLongAsByteArray(presentedDigit, i);
                xor(presentedDigit, previousBlock);
                byte[] encoded = algorithm.encode(presentedDigit);
                cypherInformant.addProcessedBytes(read);

                xor(buffer, encoded);
                outputStream.write(buffer);

                System.arraycopy(buffer, 0, previousBlock, 0, bufferSize);

                i += delta;
            }
        }
    }

    @Override
    public void decode(File inputFile, File outputFile, CypherInformant cypherInformant) throws IOException {
        try (
                InputStream inputStream = new BufferedInputStream(new FileInputStream(inputFile));
                OutputStream outputStream = new BufferedOutputStream(new FileOutputStream(outputFile));
        ) {
            long i = startDigit;
            boolean isFirstDecode = true;
            byte[] encoded = null;

            byte[] previousBlock = new byte[bufferSize];
            System.arraycopy(hash, 0, previousBlock, 0, bufferSize);

            long read;
            byte[] presentedDigit = new byte[bufferSize];
            while ((read = inputStream.read(buffer, 0, bufferSize)) != -1) {
                if (isFirstDecode) {
                    isFirstDecode = false;
                } else {
                    outputStream.write(encoded);

                    i += delta;
                }

                presentLongAsByteArray(presentedDigit, i);
                xor(presentedDigit, previousBlock);
                encoded = algorithm.encode(presentedDigit);
                cypherInformant.addProcessedBytes(bufferSize);

                System.arraycopy(buffer, 0, previousBlock, 0, bufferSize);

                xor(encoded, buffer);
            }
            if (!isFirstDecode) {
                int position = PKCS7.getPositionOfFinishByte(encoded);
                outputStream.write(encoded, 0, position);
            }
        }
    }
}
