package com.company.crypto.aesImpl.mode.fabric;

import com.company.crypto.aesImpl.algorithm.SymmetricalBlockEncryptionAlgorithm;
import com.company.crypto.aesImpl.mode.SymmetricalBlockModeCypher;


public abstract class SymmetricalBlockCypherFabric {
    public enum ArgPosition {
        IV(0), INDEX_FOR_CTR(0), HASH(1);
        public final int position;

        ArgPosition(int position) {
        this.position = position;
    }
    }

    public abstract SymmetricalBlockModeCypher create(
            SymmetricalBlockEncryptionAlgorithm algorithm,
            Object... args
    );

    protected void checkInitialVector(Object... args) {
        int positionOfInitialVector = ArgPosition.IV.position;
        if (args.length <= positionOfInitialVector) {
            throw new IllegalArgumentException("Wrong args length. No init vector");
        }
    }

    protected void checkInitialVectorSize(SymmetricalBlockEncryptionAlgorithm algorithm, byte[] IV) {
        if (IV.length != algorithm.getOpenTextBlockSizeInBytes()) {
            throw new IllegalArgumentException("Wrong IV size");
        }
    }
}
