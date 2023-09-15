package javaapplication1;
import java.security.SecureRandom;
import java.util.Arrays;
/**
public class AES{
  /*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Main.java to edit this template
 */

 *
 * @author Abenezer Ashenafi
 * @email: asgbami@gmail.com
 */


private static final int BLOCK_SIZE = 16;
    
private static final int[] S_BOX = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};


    private static final int[] INV_S_BOX = { 
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};
    private static final int[] R_CON = { 
        0x00000000, 0x00000001, 0x00000002, 0x00000004,
        0x00000008, 0x00000010, 0x00000020, 0x00000040,
        0x00000080, 0x0000001b, 0x00000036, 0x0000006c,
        0x000000d8, 0x000000ab, 0x0000004d, 0x0000009a,
        0x0000002f, 0x0000005e, 0x000000bc, 0x00000063,
        0x000000c6, 0x00000097, 0x00000035, 0x0000006a,
        0x000000d4, 0x000000b3, 0x0000007d, 0x000000fa,
        0x000000ef, 0x000000c5, 0x00000091, 0x00000039
    };

private static final int[] MIX_COL_MATRIX = {
    0x02, 0x03, 0x01, 0x01,
    0x01, 0x02, 0x03, 0x01,
    0x01, 0x01, 0x02, 0x03,
    0x03, 0x01, 0x01, 0x02
};

private static final int[] INV_MIX_COL_MATRIX = {
    0x0e, 0x0b, 0x0d, 0x09,
    0x09, 0x0e, 0x0b, 0x0d,
    0x0d, 0x09, 0x0e, 0x0b,
    0x0b, 0x0d, 0x09, 0x0e
};


    public static byte[] generateKey(int keySize) {
        byte[] key = new byte[keySize / 8];
	SecureRandom secureRandom = new SecureRandom();
    	secureRandom.nextBytes(key);
        System.out.println("from the generate key function" + key);
        return key;
    }

    public static byte[] encrypt(byte[] plaintext, byte[] key) {
        int numRounds = 0;
        int blockSize = BLOCK_SIZE;
        if (key.length == 24) {
            numRounds = 12;
            blockSize = 24;
        } else if (key.length == 32) {
            numRounds = 14;
            blockSize = 32;
        } else {
            numRounds = 10;
        }
        int[] expandedKey = expandKey(key, blockSize, numRounds);
        byte[] state = new byte[BLOCK_SIZE];
        byte[] ciphertext = new byte[plaintext.length];
        System.out.println("length of the plain text" + plaintext.length);
        for (int i = 0; i < plaintext.length; i += BLOCK_SIZE) {
            System.out.println("increment" + plaintext.length);
            for (int j = 0; j < BLOCK_SIZE; j++) {
                state[j] = plaintext[i+j];
                System.out.println(state[j]);

            }
            addRoundKey(state, expandedKey,0, blockSize);
            for (int round = 1; round < numRounds; round++) {
                subBytes(state, S_BOX);
                shiftRows(state);
                mixColumns(state, MIX_COL_MATRIX);
                addRoundKey(state, expandedKey, round * blockSize, blockSize);
            }
            subBytes(state, S_BOX);
            shiftRows(state);
            addRoundKey(state, expandedKey, numRounds * blockSize, blockSize);
            for (int j = 0; j < BLOCK_SIZE; j++) {
                ciphertext[i + j] = state[j];
            }
        }
        return ciphertext;
    }

    public static byte[] decrypt(byte[] ciphertext, byte[] key) {
        int numRounds = 0;
        int blockSize = BLOCK_SIZE;
        if (key.length == 24) {
            numRounds = 12;
            blockSize = 24;
        } else if (key.length == 32) {
            numRounds = 14;
            blockSize = 32;
        } else {
            numRounds = 10;
        }
        int[] expandedKey = expandKey(key, blockSize, numRounds);
        byte[] state = new byte[BLOCK_SIZE];
        byte[] plaintext = new byte[ciphertext.length];
        for (int i = 0; i < ciphertext.length; i += BLOCK_SIZE) {
            for (int j = 0; j < BLOCK_SIZE; j++) {
                state[j] = ciphertext[i + j];
            }
            addRoundKey(state, expandedKey, numRounds * blockSize, blockSize);
            invShiftRows(state);
            invSubBytes(state, INV_S_BOX);
            for (int round = numRounds - 1; round > 0; round--) {
                addRoundKey(state, expandedKey, round * blockSize, blockSize);
                invMixColumns(state, INV_MIX_COL_MATRIX);
                invShiftRows(state);
                invSubBytes(state, INV_S_BOX);
            }
            addRoundKey(state, expandedKey, 0, blockSize);
            for (int j = 0; j < BLOCK_SIZE; j++) {
                plaintext[i + j] = state[j];
            }
        }
        return plaintext;
    }
//expanded function for expanded key
    private static int[] expandKey(byte[] key, int blockSize, int numRounds) {
        int expandedKeySize = (numRounds + 1) * blockSize;
        int[] expandedKey = new int[expandedKeySize];
        int wordsPerBlock = blockSize / 4;
        for (int i = 0; i < wordsPerBlock; i++) {
            expandedKey[i] = (key[4 * i] << 24) | (key[4 * i + 1] << 16) | (key[4 * i + 2] << 8) | key[4 * i + 3];
        }
        int numWords = wordsPerBlock * (numRounds + 1);
        for (int i = wordsPerBlock; i < numWords; i++) {
            int  temp = expandedKey[i - 1];
            if (i % wordsPerBlock == 0) {
int[] wordArray = new int[4];
wordArray[0] = (temp >> 24) & 0xff;
wordArray[1] = (temp >> 16) & 0xff;
wordArray[2] = (temp >> 8) & 0xff;
wordArray[3] = temp & 0xff;
int[] byteArray = new int [4];
byteArray = rotWord(wordArray);
int result = ((byteArray[0] & 0xff) << 24) |
             ((byteArray[1] & 0xff) << 16) |
             ((byteArray[2] & 0xff) << 8) |
             (byteArray[3] & 0xff);



                temp = subWord(result) ^ R_CON[i / wordsPerBlock];
            } else if (wordsPerBlock > 6 && i % wordsPerBlock == 4) {
                temp = subWord(temp);
            }
            expandedKey[i] = expandedKey[i - wordsPerBlock] ^ temp;
        }
        return expandedKey;
    }
    private static int subWord(int word) {
        int result = 0;
        result |= (S_BOX[(word >> 24) & 0xff] << 24);
        result |= (S_BOX[(word >> 16) & 0xff] << 16);
        result |= (S_BOX[(word >> 8) & 0xff] << 8);
        result |= (S_BOX[word & 0xff]);
        return result;
    }
    private static int[] rotWord(int[] word) {
        int temp = word[0];
        word[0] = word[1];
        word[1] = word[2];
        word[2] = word[3];
        word[3] = temp;
        return word;
    }

    private static void addRoundKey(byte[] state, int[] expandedKey, int keyOffset, int blockSize) {
        System.out.println("from add round key function initail starting at " + expandedKey[0]);
        int wordsPerBlock = blockSize / 4;
        for (int i = 0; i < wordsPerBlock; i++) {
            System.out.println("add round key loop iteration");
            int keyWord = expandedKey[keyOffset / 4 + i];
            int stateByteOffset = i * 4;
            state[stateByteOffset] ^= (keyWord >>> 24) & 0xff;
            state[stateByteOffset + 1] ^= (keyWord >>> 16) & 0xff;
            state[stateByteOffset + 2] ^= (keyWord >>> 8) & 0xff;
            state[stateByteOffset + 3] ^= keyWord & 0xff;
        }
    }

    private static void subBytes(byte[] state, int[] sBox) {
    for (int i = 0; i < state.length; i++) {
        int row = (state[i] >> 4) & 0x0f;
        int col = state[i] & 0x0f;
        state[i] = (byte) sBox[row * 16 + col];
        System.out.println("from sub bytes function" + state[i]);
    }
}

private static void shiftRows(byte[] state) {
    byte[] temp = new byte[BLOCK_SIZE];
    for (int i = 0; i < BLOCK_SIZE; i++) {
        temp[i] = state[i];
        System.out.println("from shift rows function iteration" + state[i]);
    }
    state[1] = temp[5];
    state[5] = temp[9];
    state[9] = temp[13];
    state[13] = temp[1];
    state[2] = temp[10];
    state[6] = temp[14];
    state[10] = temp[2];
    state[14] = temp[6];
    state[3] = temp[15];
    state[7] = temp[3];
    state[11] = temp[7];
    state[15] = temp[11];
}
private static void mixColumns(byte[] state, int[] mixColMatrix) {
    System.out.println("from mix columns function entry");
    byte[] temp = new byte[BLOCK_SIZE];
    for (int i = 0; i < BLOCK_SIZE; i += 4) {
        System.out.println("from mix columns function" + i + "iterattion");
        for (int j = 0; j < 4; j++) {
            System.out.println("from mix columns function" + j + "iterattion");
    byte[] temp1,temp2,temp3,temp4;

    
    
    
temp[i + j] = (byte) (mul((byte) (mixColMatrix[j * 4] & 0xff), state[i]) ^ mul((byte)(mixColMatrix[j * 4 + 1] & 0xff), state[i + 1]) ^ 
        mul((byte)(mixColMatrix[j * 4 + 2] & 0xff), state[i + 2]) ^ mul((byte)(mixColMatrix[j * 4 + 3] & 0xff), state[i + 3]));
System.out.println("from mix columns function" + temp[i + j]);        
}
    }
    for (int i = 0; i < BLOCK_SIZE; i++) {
        state[i] = temp[i];
        System.out.println("from mix columns function" + state[i]);
    }
}

private static byte mul(byte a, byte b) {
    System.out.println("entery of gmul function");
    byte p = 0;
    byte hi_bit_set;
    for (int counter = 0; counter < 8; counter++) {
        if ((b & 1) != 0) {
            p ^= a;
        }
        hi_bit_set = (byte) (a & 0x80);
        a <<= 1;
        if (hi_bit_set != 0) {
            a ^= 0x1b; /* x^8 + x^4 + x^3 + x + 1 */
        }
        b >>= 1;
    }
    System.out.println("result of multipication:" + p);
    return p;
}

/*
private static byte mul(int a, byte b) {
    System.out.println("from mul function" + a + " " + b);
    int result = 0;
    while (b != 0) {
        if ((b & 1) != 0) {
            result ^= a;
            System.out.println("while loop multipication"+b);
        }
        boolean carry = (a & 0x80) != 0;
        a <<= 1;
        if (carry) {
            a ^= 0x1b;
        }
        b >>= 1;
    }
    System.out.println("from mul function" + (byte) (result & 0xff));
    return (byte) (result & 0xff);
}
*/


private static void invMixColumns(byte[] state, int[] invMixColMatrix) {
    byte[] temp = new byte[BLOCK_SIZE];
    for (int i = 0; i < BLOCK_SIZE; i += 4) {
        for (int j = 0; j < 4; j++) {
            temp[i + j] = (byte) (mul((byte)(invMixColMatrix[j * 4] & 0xff), state[i]) ^ mul((byte)(invMixColMatrix[j * 4 + 1]  & 0xff), state[i + 1])
                    ^ mul((byte)(invMixColMatrix[j * 4 + 2] & 0xff), state[i + 2]) ^ mul((byte)(invMixColMatrix[j * 4 + 3] & 0xff), state[i + 3]));
        }
    }
    for (int i = 0; i < BLOCK_SIZE; i++) {
        state[i] = temp[i];
    }
}


private static void invShiftRows(byte[] state) {
    byte[] temp = new byte[BLOCK_SIZE];
    for (int i = 0; i < BLOCK_SIZE; i++) {
        temp[i] = state[i];
    }
    state[1] = temp[13];
    state[5] = temp[1];
    state[9] = temp[5];
    state[13] = temp[9];
    state[2] = temp[10];
    state[6] = temp[14];
    state[10] = temp[2];
    state[14] = temp[6];
    state[3] = temp[7];
    state[7] = temp[11];
    state[11] = temp[15];
    state[15] = temp[3];
}
private static void invSubBytes(byte[] state, int[] invSBox) {
    for (int i = 0; i < state.length; i++) {
        int row = (state[i] >> 4) & 0x0f;
        int col = state[i] & 0x0f;
        state[i] = (byte) invSBox[row * 16 + col];
    }
}


public static void main(String[] args) {
    // Set the key size in bits
    int keySize = 128;

    // Generate a random key
    byte[] key = generateKey(keySize);

    // Set the plaintext
    byte[] plaintext = "Helloo, world!!!".getBytes();
    System.out.println( "from main function plain text" + plaintext);
    // Encrypt the plaintext using AES encryption
    byte[] ciphertext = encrypt(plaintext, key);

    // Decrypt the ciphertext using AES decryption
  byte[] decryptedText = decrypt(ciphertext, key);

    // Print the results
    System.out.println("Plaintext: " + new String(plaintext));
    System.out.println("Key: " + Arrays.toString(key));
    System.out.println("Ciphertext: " + Arrays.toString(ciphertext));
   System.out.println("Decrypted text: " + new String(decryptedText));
}


 
}


