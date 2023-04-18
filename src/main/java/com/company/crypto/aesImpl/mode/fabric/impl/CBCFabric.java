package com.company.crypto.aesImpl.mode.fabric.impl;

import com.company.crypto.aesImpl.algorithm.SymmetricalBlockEncryptionAlgorithm;
import com.company.crypto.aesImpl.mode.SymmetricalBlockModeCypher;
import com.company.crypto.aesImpl.mode.fabric.SymmetricalBlockCypherFabric;
import com.company.crypto.aesImpl.mode.impl.CBCCypher;

import java.util.Objects;

public class CBCFabric extends SymmetricalBlockCypherFabric {
    @Override
    public SymmetricalBlockModeCypher create(SymmetricalBlockEncryptionAlgorithm algorithm, Object... args) {
        Objects.requireNonNull(args);

        checkInitialVector(args);

        int positionOfInitialVector = ArgPosition.IV.position;
        byte[] IV = (byte[])(args[positionOfInitialVector]);
        checkInitialVectorSize(algorithm, IV);

        return new CBCCypher(algorithm, IV);
    }
}
