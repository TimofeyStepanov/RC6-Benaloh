package com.company.cripto.aesImpl.mode.impl;

import com.company.cripto.aesImpl.algorithm.SymmetricalBlockEncryptionAlgorithm;
import com.company.cripto.aesImpl.mode.SymmetricalBlockModeCypher;
import com.company.cripto.aesImpl.padding.PKCS7;
import lombok.Builder;

import java.io.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.Callable;


public class CBCCypher extends SymmetricalBlockModeCypher {
    private final byte[] initialVector;

    public CBCCypher(SymmetricalBlockEncryptionAlgorithm algorithm, byte[] initialVector) {
        super(algorithm, Runtime.getRuntime().availableProcessors()-1);
        this.initialVector = initialVector;
    }

    @Override
    public void encode(File inputFile, File outputFile) throws IOException {
        try (
                InputStream inputStream = new BufferedInputStream(new FileInputStream(inputFile));
                OutputStream outputStream = new BufferedOutputStream(new FileOutputStream(outputFile));
        ) {
            byte[] toXor = initialVector;
            long read;

            while ((read = inputStream.read(buffer, 0, bufferSize)) != -1) {
                if (read < bufferSize) {
                    PKCS7.doPadding(buffer, (int) (bufferSize - read));
                }

                xor(buffer, toXor);
                byte[] encoded = algorithm.encode(buffer);

                outputStream.write(encoded);

                toXor = encoded;
            }
        }
    }

    @Override
    public void decode(File inputFile, File outputFile) throws IOException {
        long fileLengthInByte = inputFile.length();
        long blockNumber = fileLengthInByte / bufferSize;

        List<Callable<Void>> callableList = new ArrayList<>();
        if (blockNumber < threadNumber || threadNumber < 2) {
            Callable<Void> decodeCallable = CBCDecodeFile.builder()
                    .filePositionToStart(0)
                    .byteToEncode(fileLengthInByte)
                    .bufferSize(bufferSize)
                    .initialVector(initialVector)
                    .algorithm(algorithm)
                    .inputFile(new RandomAccessFile(inputFile, "r"))
                    .outputFile(new RandomAccessFile(outputFile, "rw"))
                    .build();
            callableList.add(decodeCallable);
        } else {
            long endOfPreviousBlock = 0;
            for (int i = 0; i < threadNumber-1; i++) {
                Callable<Void> decodeCallable = CBCDecodeFile.builder()
                        .filePositionToStart(endOfPreviousBlock)
                        .byteToEncode(blockNumber / threadNumber * bufferSize)
                        .bufferSize(bufferSize)
                        .initialVector(initialVector)
                        .algorithm(algorithm)
                        .inputFile(new RandomAccessFile(inputFile, "r"))
                        .outputFile(new RandomAccessFile(outputFile, "rw"))
                        .build();
                callableList.add(decodeCallable);

                endOfPreviousBlock += blockNumber/threadNumber * bufferSize;
            }

            Callable<Void> decodeCallable = CBCDecodeFile.builder()
                    .filePositionToStart(endOfPreviousBlock)
                    .byteToEncode(fileLengthInByte - endOfPreviousBlock)
                    .bufferSize(bufferSize)
                    .initialVector(initialVector)
                    .algorithm(algorithm)
                    .inputFile(new RandomAccessFile(inputFile, "r"))
                    .outputFile(new RandomAccessFile(outputFile, "rw"))
                    .build();
            callableList.add(decodeCallable);
        }
        callTasksAndWait(callableList);
    }
}

@Builder
class CBCDecodeFile implements Callable<Void> {
    private final long filePositionToStart;
    private final long byteToEncode;
    private final int bufferSize;
    private final RandomAccessFile inputFile;
    private final RandomAccessFile outputFile;
    private final SymmetricalBlockEncryptionAlgorithm algorithm;
    private final byte[] initialVector;

    private byte[] buffer;

    @Override
    public Void call() throws IOException {
        buffer = new byte[bufferSize];

        inputFile.seek(filePositionToStart);
        outputFile.seek(filePositionToStart);

        try (
                InputStream inputStream = new BufferedInputStream(new FileInputStream(inputFile.getFD()));
                OutputStream outputStream = new BufferedOutputStream(new FileOutputStream(outputFile.getFD()));
        ) {
            boolean isFirstDecode = true;
            byte[] decoded = null;

            byte[] toXor;
            byte[] previousBuffer = new byte[bufferSize];
            System.arraycopy(getInitialVector(inputStream), 0, previousBuffer, 0, bufferSize);

            long read;
            long allReadBytes = 0;
            while ((read = inputStream.read(buffer, 0, bufferSize)) != -1 && allReadBytes <= byteToEncode) {
                if (isFirstDecode) {
                    isFirstDecode = false;
                } else {
                    outputStream.write(decoded);
                }

                decoded = algorithm.decode(buffer);

                toXor = previousBuffer;
                xor(decoded, toXor);
                System.arraycopy(buffer, 0, previousBuffer, 0, decoded.length);

                allReadBytes += read;
            }
            if (!isFirstDecode) {
                int position = PKCS7.getPositionOfFinishByte(decoded);
                outputStream.write(decoded, 0, position);
            }
        }
        return null;
    }

    private byte[] getInitialVector(InputStream inputStream) throws IOException {
        if (inputFile.getFilePointer() == 0) {
            return initialVector;
        }

        inputFile.seek(inputFile.getFilePointer() - bufferSize);
        if (inputStream.read(buffer, 0, bufferSize) != bufferSize) {
            throw new IllegalArgumentException("Wrong file position!");
        }
        return buffer;
    }

    private void xor(byte[] array1, byte[] array2) {
        for (int i = 0; i < array1.length; i++) {
            array1[i] = (byte) (array1[i] ^ array2[i]);
        }
    }
}

@Builder
class CTREncodeFile implements Callable<Void> {
    private byte[] buffer;

    private final long filePositionToStart;
    private final long byteToEncode;
    private final long indexToStart;
    private final int bufferSize;
    private final int delta;
    private final RandomAccessFile inputFile;
    private final RandomAccessFile outputFile;
    private final SymmetricalBlockEncryptionAlgorithm algorithm;

    @Override
    public Void call() throws Exception {
        buffer = new byte[bufferSize];

        inputFile.seek(filePositionToStart);
        outputFile.seek(filePositionToStart);

        try (
                InputStream inputStream = new BufferedInputStream(new FileInputStream(inputFile.getFD()));
                OutputStream outputStream = new BufferedOutputStream(new FileOutputStream(outputFile.getFD()));
        ) {
            long i = indexToStart;
            long allReadBytes = 0;
            long read;

            byte[] presentedDigit = new byte[bufferSize];
            while ((read = inputStream.read(buffer, 0, bufferSize)) != -1 && allReadBytes <= byteToEncode) {
                if (read < bufferSize) {
                    PKCS7.doPadding(buffer, (int) (bufferSize - read));
                }

                presentLongAsByteArray(presentedDigit, i);
                byte[] encoded = algorithm.encode(presentedDigit);

                xor(buffer, encoded);
                outputStream.write(buffer);

                allReadBytes += read;
                i += delta;
            }
        }
        return null;
    }
    private void xor(byte[] buffer, byte[] array) {
        for (int i = 0; i < bufferSize; i++) {
            buffer[i] = (byte) (buffer[i] ^ array[i]);
        }
    }
    private void presentLongAsByteArray(byte[] buffer, long digit) {
        Arrays.fill(buffer, (byte) 0);
        for (int i = 0; i < buffer.length; i++) {
            buffer[buffer.length - i - 1] = (byte) (digit & 0xFF);
            digit >>= Byte.SIZE;
        }
    }
}



