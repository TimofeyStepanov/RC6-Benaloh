package com.company.cripto.aesImpl.mode.fabric;

import com.company.cripto.aesImpl.algorithm.SymmetricalBlockEncryptionAlgorithm;
import com.company.cripto.aesImpl.mode.SymmetricalBlockModeCypher;


public abstract class SymmetricalBlockCypherFabric {
    public enum ArgPosition {
        IV(0), INDEX_FOR_CTR(1), HASH(2);

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
