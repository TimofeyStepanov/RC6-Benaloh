package com.company.crypto.aesImpl.mode.fabric.impl;


import com.company.crypto.aesImpl.algorithm.SymmetricalBlockEncryptionAlgorithm;
import com.company.crypto.aesImpl.mode.SymmetricalBlockModeCypher;
import com.company.crypto.aesImpl.mode.fabric.SymmetricalBlockCypherFabric;
import com.company.crypto.aesImpl.mode.impl.RDPlusHCypher;

import java.util.Objects;

public class RDPlusHFabric extends SymmetricalBlockCypherFabric {
    @Override
    public SymmetricalBlockModeCypher create(SymmetricalBlockEncryptionAlgorithm algorithm, Object... args) {
        Objects.requireNonNull(args);

        int positionOfInitialVector = ArgPosition.IV.position;
        int positionOfHash = ArgPosition.HASH.position;
        if (args.length <= positionOfInitialVector || args.length <= positionOfHash) {
            throw new IllegalArgumentException("Wrong args length. No init vector");
        }

        byte[] IV = (byte[])(args[positionOfInitialVector]);
        if (IV.length != algorithm.getOpenTextBlockSizeInBytes()) {
            throw new IllegalArgumentException("Wrong IV size");
        }

        byte[] hash = (byte[])(args[positionOfHash]);
        if (hash.length != algorithm.getOpenTextBlockSizeInBytes()) {
            throw new IllegalArgumentException("Wrong hash size");
        }
        return new RDPlusHCypher(algorithm,  IV, hash);
    }
}
