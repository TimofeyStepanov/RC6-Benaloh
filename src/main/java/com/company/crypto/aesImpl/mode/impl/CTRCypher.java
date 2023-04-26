package com.company.crypto.aesImpl.mode.impl;

import com.company.crypto.aesImpl.CypherInformant;
import com.company.crypto.aesImpl.algorithm.SymmetricalBlockEncryptionAlgorithm;
import com.company.crypto.aesImpl.mode.SymmetricalBlockModeCypher;
import com.company.crypto.aesImpl.padding.PKCS7;
import lombok.Builder;

import java.io.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.Callable;

public class CTRCypher extends SymmetricalBlockModeCypher {
    protected long startDigit;
    protected int delta;

    public CTRCypher(SymmetricalBlockEncryptionAlgorithm algorithm, int startDigit) {
        super(algorithm, Runtime.getRuntime().availableProcessors() - 1);

        this.startDigit = startDigit;
        this.delta = 1;
    }

    @Override
    public void encode(File inputFile, File outputFile, CypherInformant cypherInformant) throws IOException {
        long fileLengthInByte = inputFile.length();
        long blockNumber = fileLengthInByte / bufferSize;

        List<Callable<Void>> callableList = new ArrayList<>();
        if (blockNumber < threadNumber || threadNumber < 2) {
            Callable<Void> encodeCallable = CTREncodeFile.builder()
                    .filePositionToStart(0)
                    .byteToEncode(fileLengthInByte)
                    .indexToStart(this.startDigit)
                    .delta(delta)
                    .bufferSize(bufferSize)
                    .cypherInformant(cypherInformant)
                    .algorithm(algorithm)
                    .inputFile(new RandomAccessFile(inputFile, "r"))
                    .outputFile(new RandomAccessFile(outputFile, "rw"))
                    .build();
            callableList.add(encodeCallable);
        } else {
            long endOfPreviousBlock = 0;
            for (int i = 0; i < threadNumber - 1; i++) {
                Callable<Void> encodeCallable = CTREncodeFile.builder()
                        .filePositionToStart(endOfPreviousBlock)
                        .byteToEncode(blockNumber / threadNumber * bufferSize)
                        .indexToStart(endOfPreviousBlock / bufferSize * delta + startDigit)
                        .delta(delta)
                        .bufferSize(bufferSize)
                        .cypherInformant(cypherInformant)
                        .algorithm(algorithm)
                        .inputFile(new RandomAccessFile(inputFile, "r"))
                        .outputFile(new RandomAccessFile(outputFile, "rw"))
                        .build();
                callableList.add(encodeCallable);

                endOfPreviousBlock += blockNumber / threadNumber * bufferSize;
            }

            Callable<Void> encodeCallable = CTREncodeFile.builder()
                    .filePositionToStart(endOfPreviousBlock)
                    .byteToEncode(fileLengthInByte - endOfPreviousBlock)
                    .indexToStart(endOfPreviousBlock / bufferSize * delta + startDigit)
                    .delta(delta)
                    .bufferSize(bufferSize)
                    .cypherInformant(cypherInformant)
                    .algorithm(algorithm)
                    .inputFile(new RandomAccessFile(inputFile, "r"))
                    .outputFile(new RandomAccessFile(outputFile, "rw"))
                    .build();
            callableList.add(encodeCallable);
        }
        callTasksAndWait(callableList);
    }

    @Override
    public void decode(File inputFile, File outputFile, CypherInformant cypherInformant) throws IOException {
        long fileLengthInByte = inputFile.length();
        long blockNumber = fileLengthInByte / bufferSize;

        List<Callable<Void>> callableList = new ArrayList<>();
        if (blockNumber < threadNumber || threadNumber < 2) {
            Callable<Void> decodeCallable = CTRDecodeFile.builder()
                    .filePositionToStart(0)
                    .byteToEncode(fileLengthInByte)
                    .startDigit(this.startDigit)
                    .delta(delta)
                    .cypherInformant(cypherInformant)
                    .bufferSize(bufferSize)
                    .algorithm(algorithm)
                    .inputFile(new RandomAccessFile(inputFile, "r"))
                    .outputFile(new RandomAccessFile(outputFile, "rw"))
                    .build();
            callableList.add(decodeCallable);
        } else {
            long endOfPreviousBlock = 0;
            for (int i = 0; i < threadNumber - 1; i++) {
                Callable<Void> decodeCallable = CTRDecodeFile.builder()
                        .filePositionToStart(endOfPreviousBlock)
                        .byteToEncode(blockNumber / threadNumber * bufferSize)
                        .bufferSize(bufferSize)
                        .delta(delta)
                        .cypherInformant(cypherInformant)
                        .startDigit(endOfPreviousBlock / bufferSize * delta + startDigit)
                        .algorithm(algorithm)
                        .inputFile(new RandomAccessFile(inputFile, "r"))
                        .outputFile(new RandomAccessFile(outputFile, "rw"))
                        .build();
                callableList.add(decodeCallable);

                endOfPreviousBlock += blockNumber / threadNumber * bufferSize;
            }

            Callable<Void> decodeCallable = CTRDecodeFile.builder()
                    .filePositionToStart(endOfPreviousBlock)
                    .byteToEncode(fileLengthInByte - endOfPreviousBlock)
                    .bufferSize(bufferSize)
                    .delta(delta)
                    .cypherInformant(cypherInformant)
                    .startDigit(endOfPreviousBlock / bufferSize * delta + startDigit)
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
class CTREncodeFile implements Callable<Void> {
    private byte[] buffer;

    private final long filePositionToStart;
    private final long byteToEncode;
    private final long indexToStart;
    private final int bufferSize;
    private final CypherInformant cypherInformant;
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
                cypherInformant.addProcessedBytes(read);

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

@Builder
class CTRDecodeFile implements Callable<Void> {
    private byte[] buffer;

    private final long filePositionToStart;
    private final long byteToEncode;
    private final long startDigit;
    private final int bufferSize;
    private final int delta;
    private final CypherInformant cypherInformant;
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
            long i = startDigit;
            boolean isFirstDecode = true;
            byte[] encoded = null;

            byte[] presentedDigit = new byte[bufferSize];
            long allReadBytes = 0, read;
            while ((read = inputStream.read(buffer, 0, bufferSize)) != -1 && allReadBytes <= byteToEncode) {
                if (isFirstDecode) {
                    isFirstDecode = false;
                } else {
                    outputStream.write(encoded);
                    i += delta;
                }

                presentLongAsByteArray(presentedDigit, i);
                encoded = algorithm.encode(presentedDigit);
                cypherInformant.addProcessedBytes(bufferSize);
                xor(encoded, buffer);

                allReadBytes += read;
            }
            if (!isFirstDecode) {
                int position = PKCS7.getPositionOfFinishByte(encoded);
                outputStream.write(encoded, 0, position);
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

