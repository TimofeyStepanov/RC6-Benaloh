package com.company.crypto.aesImpl;


import com.company.crypto.aesImpl.algorithm.SymmetricalBlockEncryptionAlgorithm;
import com.company.crypto.aesImpl.mode.SymmetricalBlockMode;
import com.company.crypto.aesImpl.mode.SymmetricalBlockModeCypher;
import com.company.crypto.aesImpl.mode.fabric.SymmetricalBlockCypherFabric;
import com.company.crypto.aesImpl.mode.fabric.impl.*;

import java.io.Closeable;
import java.io.File;
import java.io.IOException;
import java.util.EnumMap;
import java.util.Map;
import java.util.Objects;

/**
 * com.company.Main encoder/decoder. Get symmetric algorithm (64 bit encoder/decoder), mode, and other param.
 **/
public final class SymmetricBlockCypher implements Closeable {
    private static final Map<SymmetricalBlockMode, SymmetricalBlockCypherFabric> modeAndItsFabric = new EnumMap<>(SymmetricalBlockMode.class);
    static {
        modeAndItsFabric.put(SymmetricalBlockMode.ECB, new ECBFabric());
        modeAndItsFabric.put(SymmetricalBlockMode.CBC, new CBCFabric());
        modeAndItsFabric.put(SymmetricalBlockMode.OFB, new OFBFabric());
        modeAndItsFabric.put(SymmetricalBlockMode.CFB, new CFBFabric());
        modeAndItsFabric.put(SymmetricalBlockMode.CTR, new CTRFabric());
        modeAndItsFabric.put(SymmetricalBlockMode.RD, new RDFabric());
        modeAndItsFabric.put(SymmetricalBlockMode.RDPlusCypherH, new RDPlusHFabric());
    }

    public static SymmetricBlockCypher build(byte[] key,
                                             SymmetricalBlockMode symmetricalBlockMode,
                                             SymmetricalBlockEncryptionAlgorithm algorithm,
                                             Object ... args) {
        Objects.requireNonNull(key);
        Objects.requireNonNull(symmetricalBlockMode);
        Objects.requireNonNull(algorithm);

        return new SymmetricBlockCypher(key, symmetricalBlockMode, algorithm, args);
    }

    private final SymmetricalBlockModeCypher symmetricalBlockCypher;
    private final SymmetricalBlockEncryptionAlgorithm algorithm;
    private SymmetricBlockCypher(byte[] key,
                                 SymmetricalBlockMode mode,
                                 SymmetricalBlockEncryptionAlgorithm algorithm,
                                 Object ... args) {
        this.algorithm = algorithm;
        algorithm.setKey(key);

        SymmetricalBlockCypherFabric cypherFabric = modeAndItsFabric.get(mode);
        this.symmetricalBlockCypher = cypherFabric.create(algorithm, args);
    }

    public void encode(File inputFile, File outputFile) throws IOException {
        Objects.requireNonNull(inputFile);
        Objects.requireNonNull(outputFile);

        symmetricalBlockCypher.encode(inputFile, outputFile);
    }

    public void decode(File inputFile, File outputFile) throws IOException {
        Objects.requireNonNull(inputFile);
        Objects.requireNonNull(outputFile);

        symmetricalBlockCypher.decode(inputFile, outputFile);
    }

    public void setKey(byte[] key) {
        this.algorithm.setKey(key);
    }

    @Override
    public void close() {
        symmetricalBlockCypher.close();
    }
}
