package com.company;

import java.nio.ByteBuffer;

public class Main {
    public static void main(String[] args) {
        long digit = 1L << 35;
        digit += 1;
        digit += 4;

        int translated = (int)(digit & ((1L << Integer.SIZE) - 1));
        System.out.println(translated);

        System.out.println((int)digit);
    }
}
