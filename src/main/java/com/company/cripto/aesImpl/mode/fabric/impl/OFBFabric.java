package com.company.cripto.aesImpl.mode.fabric.impl;


import com.company.cripto.aesImpl.algorithm.SymmetricalBlockEncryptionAlgorithm;
import com.company.cripto.aesImpl.mode.SymmetricalBlockModeCypher;
import com.company.cripto.aesImpl.mode.fabric.SymmetricalBlockCypherFabric;
import com.company.cripto.aesImpl.mode.impl.OFBCypher;

import java.util.Objects;

public class OFBFabric extends SymmetricalBlockCypherFabric {
    @Override
    public SymmetricalBlockModeCypher create(SymmetricalBlockEncryptionAlgorithm algorithm, Object... args) {
        Objects.requireNonNull(args);

        checkInitialVector(args);

        int positionOfInitialVector = ArgPosition.IV.position;
        byte[] IV = (byte[])(args[positionOfInitialVector]);
        checkInitialVectorSize(algorithm, IV);

        return new OFBCypher(algorithm, IV);
    }
}
