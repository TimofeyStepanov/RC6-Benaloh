package com.company.cripto.aesImpl.mode.fabric.impl;


import com.company.cripto.aesImpl.algorithm.SymmetricalBlockEncryptionAlgorithm;
import com.company.cripto.aesImpl.mode.SymmetricalBlockModeCypher;
import com.company.cripto.aesImpl.mode.fabric.SymmetricalBlockCypherFabric;
import com.company.cripto.aesImpl.mode.impl.RDPlusHCypher;

import java.util.Objects;

public class RDPlusHFabric extends SymmetricalBlockCypherFabric {
    @Override
    public SymmetricalBlockModeCypher create(SymmetricalBlockEncryptionAlgorithm algorithm, Object... args) {
        Objects.requireNonNull(args);

        int positionOfInitialVector = ArgPosition.IV.position;
        int positionOfHash = ArgPosition.HASH.position;
        if (args.length <= positionOfInitialVector || args.length <= positionOfHash) {
            throw new IllegalArgumentException("Wrong args length.");
        }

        byte[] IV = (byte[])(args[positionOfInitialVector]);
        if (IV.length != algorithm.getOpenTextBlockSizeInBytes()) {
            throw new IllegalArgumentException("Wrong IV size");
        }
        return new RDPlusHCypher(algorithm,  IV, (byte[])args[positionOfHash]);
    }
}
