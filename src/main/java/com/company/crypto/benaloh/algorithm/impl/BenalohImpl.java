package com.company.crypto.benaloh.algorithm.impl;

import com.company.crypto.benaloh.algebra.discreteLogarithm.DiscreteLogarithmService;
import com.company.crypto.benaloh.algebra.discreteLogarithm.impl.SimpleDiscreteLogarithm;
import com.company.crypto.benaloh.algebra.prime.PrimeChecker;
import com.company.crypto.benaloh.algebra.prime.PrimeCheckerFabric;
import com.company.crypto.benaloh.algebra.prime.PrimeCheckerType;
import com.company.crypto.benaloh.algorithm.Benaloh;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.BitSet;
import java.util.Objects;
import java.util.Random;
import java.util.concurrent.ThreadLocalRandom;


public final class BenalohImpl extends Benaloh {
    private static final int MIN_LENGTH_OF_PRIME_DIGIT = 64;

    private OpenKey openKey;
    private PrivateKey privateKey;
    private final OpenKeyGenerator openKeyGenerator;
    private final Random random = new Random();

    private final DiscreteLogarithmService discreteLogarithmService;

    public BenalohImpl(PrimeCheckerType type, double precision, int rLength) {
        this.openKeyGenerator = new OpenKeyGenerator(type, precision, rLength);
        this.openKeyGenerator.generateOpenAndPrivateKey();

        this.discreteLogarithmService = new SimpleDiscreteLogarithm(openKey.getR());
    }

    public BenalohImpl(OpenKey openKey, PrivateKey privateKey, PrimeCheckerType type, double precision, int rLength) {
        this.openKeyGenerator = new OpenKeyGenerator(type, precision, rLength);
        this.discreteLogarithmService = new SimpleDiscreteLogarithm(openKey.getR());

        this.openKey = openKey;
        this.privateKey = privateKey;
    }

    @Override
    public byte[] encode(byte[] array, OpenKey openKey) {
        Objects.requireNonNull(array);
        Objects.requireNonNull(openKey);
        if (array.length == 0) {
            return new byte[0];
        }

        BigInteger message = translateInputByteArrayToBigInteger(array);
        //log.info("message to encode:" + message);

        BigInteger r = openKey.getR();
        if (message.compareTo(r) >= 0) {
            throw new IllegalArgumentException("Wrong message to encode:" + message);
        }

        BigInteger n = openKey.getN();
        BigInteger u;
        do {
            u = getRandomPositiveDigit(n);
        } while (!u.gcd(n).equals(BigInteger.ONE));
        //log.info("generate u:" + u);

        BigInteger y = openKey.getY();

        BigInteger yInDegree = y.modPow(message, n);
        BigInteger uInDegree = u.modPow(r, n);
        BigInteger encodedMessage = yInDegree.multiply(uInDegree).mod(n);
        //log.info("message encoded:" + encodedMessage);

        byte[] arrayOfEncodedMessage = encodedMessage.toByteArray();
        reverseArray(arrayOfEncodedMessage);
        arrayOfEncodedMessage = deleteLastElementOfArrayIfItZero(arrayOfEncodedMessage);
        return arrayOfEncodedMessage;
    }

    private BigInteger translateInputByteArrayToBigInteger(byte[] array) {
        byte[] copiedArray = Arrays.copyOf(array, array.length);
        reverseArray(copiedArray);
        return new BigInteger(1, copiedArray);
    }

    private void reverseArray(byte[] array) {
        for (int i = 0; i < array.length / 2; i++) {
            byte tmp = array[i];
            array[i] = array[array.length - 1 - i];
            array[array.length - 1 - i] = tmp;
        }
    }

    private BigInteger getRandomPositiveDigit(BigInteger maxDigit) {
        BigInteger randomDigit;
        do {
            int randomLength = Math.abs(ThreadLocalRandom.current().nextInt() % maxDigit.bitLength());
            randomDigit = new BigInteger(randomLength, random);
        } while (!(randomDigit.compareTo(BigInteger.ONE) > 0 && randomDigit.compareTo(maxDigit) < 0));
        return randomDigit;
    }

    private byte[] deleteLastElementOfArrayIfItZero(byte[] decodedMessageBytes) {
        if (decodedMessageBytes.length > 1 && decodedMessageBytes[decodedMessageBytes.length - 1] == 0) {
            return Arrays.copyOfRange(decodedMessageBytes, 0, decodedMessageBytes.length - 1);
        }
        return decodedMessageBytes;
    }

    @Override
    public byte[] decode(byte[] array) {
        Objects.requireNonNull(array);
        if (array.length == 0) {
            return new byte[0];
        }

        BigInteger f = privateKey.getF();
        BigInteger n = openKey.getN();
        BigInteger r = openKey.getR();

        BigInteger encodedMessage = translateInputByteArrayToBigInteger(array);
        //log.info("message to decode:" + encodedMessage);
        if (encodedMessage.compareTo(n) >= 0) {
            throw new IllegalArgumentException("Wrong message to decode");
        }

        BigInteger a = encodedMessage.modPow(f.divide(r), n);
        BigInteger decodedMessage = discreteLogarithmService.getDiscreteLogarithm(privateKey.getX(), a, n);
        //log.info("decoded message:" + decodedMessage);

        checkDecodedMessage(decodedMessage, a);

        byte[] arrayOfDecodedMessage = decodedMessage.toByteArray();
        reverseArray(arrayOfDecodedMessage);
        arrayOfDecodedMessage = deleteLastElementOfArrayIfItZero(arrayOfDecodedMessage);
        return arrayOfDecodedMessage;
    }

    private void checkDecodedMessage(BigInteger decodedMessage, BigInteger a) {
        BigInteger x = privateKey.getX();
        BigInteger n = openKey.getN();
        if (!x.modPow(decodedMessage, n).equals(a)) {
            throw new IllegalArgumentException("Wrong decoded message!");
        }
    }

    @Override
    public void regenerateOpenKey() {
        this.openKeyGenerator.generateOpenAndPrivateKey();
    }

    @Override
    public OpenKey getOpenKey() {
        return openKey;
    }

    class OpenKeyGenerator {
        private final PrimeChecker primeChecker;
        private final double precision;
        private final int rPrimeLength;

        public OpenKeyGenerator(PrimeCheckerType type, double precision, int rLength) {
            this.primeChecker = PrimeCheckerFabric.getInstance(type);
            this.precision = precision;
            this.rPrimeLength = rLength;
        }

        public void generateOpenAndPrivateKey() {
            BigInteger r = BigInteger.valueOf(rPrimeLength);
            BigInteger p;
            BigInteger pMinusOne;
            do {
                int randomLength = MIN_LENGTH_OF_PRIME_DIGIT + ThreadLocalRandom.current().nextInt(0, MIN_LENGTH_OF_PRIME_DIGIT);
                p = generateRandomPrimeDigit(randomLength);
                pMinusOne = p.subtract(BigInteger.ONE);
            } while (!pMinusOne.mod(r).equals(BigInteger.ZERO) || !r.gcd(pMinusOne.divide(r)).equals(BigInteger.ONE));
            //log.info("Generate p:" + p);

            BigInteger q;
            BigInteger qMinusOne;
            do {
                int randomLength = MIN_LENGTH_OF_PRIME_DIGIT + ThreadLocalRandom.current().nextInt(0, MIN_LENGTH_OF_PRIME_DIGIT);
                q = generateRandomPrimeDigit(randomLength);
                qMinusOne = q.subtract(BigInteger.ONE);
            } while (!r.gcd(qMinusOne).equals(BigInteger.ONE) || p.equals(q));
            //log.info("Generate q:" + q);

            BigInteger n = p.multiply(q);
            BigInteger f = pMinusOne.multiply(qMinusOne);
            BigInteger yDegree = f.divide(r);
            BigInteger y;
            do {
                y = BenalohImpl.this.getRandomPositiveDigit(n);
            } while (!y.gcd(n).equals(BigInteger.ONE) || y.modPow(yDegree, n).equals(BigInteger.ONE));
            //log.info("Generate y:" + y);

            BigInteger x = y.modPow(yDegree, n);

            BenalohImpl.this.openKey = new OpenKey(y, r, n);
            BenalohImpl.this.privateKey = new PrivateKey(f, x);

            checkAll(p, q);
        }

        private BigInteger generateRandomPrimeDigit(int digitLength) {
            BitSet bitSet = new BitSet(digitLength);
            bitSet.set(0, true);
            bitSet.set(digitLength - 1, true);

            BigInteger randomEvenDigit;
            do {
                for (int i = 1; i < digitLength - 1; i++) {
                    bitSet.set(i, ThreadLocalRandom.current().nextBoolean());
                }

                byte[] bitSetByteArray = bitSet.toByteArray();
                reverseArray(bitSetByteArray);
                randomEvenDigit = new BigInteger(1, bitSetByteArray);
            } while (!primeChecker.isPrime(randomEvenDigit, precision));
            return randomEvenDigit;
        }


        private void checkAll(BigInteger p, BigInteger q) {
            BigInteger f = BenalohImpl.this.privateKey.getF();
            BigInteger y = BenalohImpl.this.openKey.getY();
            BigInteger r = BenalohImpl.this.openKey.getR();
            BigInteger n = BenalohImpl.this.openKey.getN();

            if (!primeChecker.isPrime(r, precision)) {
                throw new IllegalArgumentException("Not prime");
            }
            if (!primeChecker.isPrime(q, precision)) {
                throw new IllegalArgumentException("Not prime");
            }
            if (!primeChecker.isPrime(p, precision)) {
                throw new IllegalArgumentException("Not prime");
            }
            if (y.modPow(f.divide(r), n).equals(BigInteger.ONE)) {
                throw new IllegalArgumentException("");
            }
            if (!r.gcd(p.subtract(BigInteger.ONE).divide(r)).equals(BigInteger.ONE)) {
                throw new IllegalArgumentException("r and p-1/r");
            }
            if (!r.gcd(q.subtract(BigInteger.ONE)).equals(BigInteger.ONE)) {
                throw new IllegalArgumentException("r and q-1");
            }
        }
    }
}
