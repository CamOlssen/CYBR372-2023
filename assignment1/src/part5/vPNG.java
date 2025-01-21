package com.packtpub.crypto.section5.src.part5;


/**
 * CYBR373 Assignment 1 Part 1
 * Cam Olssen (300492582)
 */
public class vPNG {
    private long seed;
    public vPNG(long seed){
        this.seed = seed;
    }

    /**
     * Method to generate random byte values based off the seed
     * @param bytes - takes an array of bytes to generate random values for
     * @return - returns the bytes
     */
    public byte[] next(byte[] bytes){
        for(int i = 0; i < bytes.length; i++){
            seed = (seed * 1103515245 + 12345) & 0x7FFFFFFF; //update the seed using an LCG formula to generate the next pseudorandom value
            bytes[i] = (byte)(seed & 0xFF); //store the least significant 8 bits of the seed as a byte
        }
        System.out.println("Random values from vPNG: "+Util.bytesToHex(bytes));
        return bytes;
    }
}
