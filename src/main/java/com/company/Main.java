package com.company;

import java.nio.ByteBuffer;

public class Main {
    public static void main(String[] args) {
        ByteBuffer byteBuffer = ByteBuffer.allocate(2 * Long.BYTES);
        byteBuffer.putLong(1);
        byteBuffer.putLong(2);

        byte[] array = byteBuffer.array();
        for (byte el : array) {
            System.out.println(el);
        }
    }
}
