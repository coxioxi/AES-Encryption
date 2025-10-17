/**
 * AES (Advanced Encryption Standard) implementation using 128-bit key encryption.
 * This class provides methods for encrypting and decrypting data using
 * the AES-128 algorithm. It operates on 16-byte (128-bit) blocks and
 * performs 10 rounds of substitution, permutation, and mixing transformations
 * based on the Rijndael cipher.
 *
 * Authors:	Samuel Costa and Abiral Pokharel
 * Course:	COMP 4290
 * Assignment:	Project 2
 * Date:	10/17/2025
 */

import java.nio.charset.StandardCharsets;

public class AES {
    byte[] key;
    public static final int MATRIX_LEN = 4;
    private static final int NUM_ROUNDS = 10;
    private static final int WORDS_IN_KEY = 4; // 4 words per key, 4 bytes each
    private static final int KEY_LENGTH = 16;
    private static final int[] RCON = {
            0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a,
            0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39,
            0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a,
            0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8,
            0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef,
            0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc,
            0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b,
            0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3,
            0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94,
            0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20,
            0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35,
            0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f,
            0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04,
            0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63,
            0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd,
            0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb
    };

    private static final int[] S_BOX = {
            0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
            0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47, 0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
            0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
            0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
            0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
            0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
            0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
            0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
            0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
            0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
            0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
            0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
            0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
            0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
            0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
            0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
    };

    private static final int[] I_S_BOX = {
            0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
            0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
            0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
            0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
            0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
            0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
            0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
            0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
            0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
            0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
            0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
            0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
            0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
            0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
            0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
            0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
    };

    public AES(byte[]key){
        this.key = key;
    }

    /**
     * Encrypts a 16-byte plaintext block using AES-128.
     * Performs key expansion, initial AddRoundKey, 9 normal rounds
     * (Substitute Bytes, Shift Rows, Mix Columns, Add Round Key), and the final round.
     *
     * @param bytes 16-byte plaintext block
     * @return 16-byte ciphertext block
     */
    public byte[] encrypt(byte[] bytes){
        byte[][] matrix = new byte[MATRIX_LEN][MATRIX_LEN]; //every 16 bytes of message
        byte[][] roundKeys = expandKey(key);

        // Load data into state matrix
        loadState(bytes, matrix);

        // Initial Round: Add round key
        addRoundKey(matrix, roundKeys[0]);

        // Normal rounds (1-9)
        for (int round = 1; round < NUM_ROUNDS; round++) {

            // Substitute bytes
            substituteByte(matrix, false);

            // Substitute bytes
            shiftRows(matrix, false);

            // Mix columns
            mixColumns(matrix);

            // Add Round Key
            addRoundKey(matrix, roundKeys[round]);
        }

        // Final round (10)

        // Substitute bytes
        substituteByte(matrix, false);
        // Shift rows here
        shiftRows(matrix, false);
        // AddRoundKey
        addRoundKey(matrix, roundKeys[10]);

        return extractMessage(matrix); //extract the cypher text
    }

    public byte[] decrypt(byte[] bytes) {
        byte[][] matrix = new byte[MATRIX_LEN][MATRIX_LEN]; //every 16 bytes of message
        byte[][] roundKeys = expandKey(key);

        // Load data into state matrix
        loadState(bytes, matrix);

        // Final round (10)

        // Add round key
        addRoundKey(matrix, roundKeys[NUM_ROUNDS]);

        // Inverse shift rows
        shiftRows(matrix, true);

        // Inverse substitute
        substituteByte(matrix, true);

        // Inverse normal rounds (9-0)
        for (int i = NUM_ROUNDS-1; i > 0; i--) {
            // Add round key
            addRoundKey(matrix, roundKeys[i]);

            // Inverse Mix Columns
            inverseMixColumns(matrix);

            // Inverse shift rows
            shiftRows(matrix, true);

            // Inverse substitute
            substituteByte(matrix, true);
        }

        // Add round key
        addRoundKey(matrix, roundKeys[0]);

        return extractMessage(matrix); //extract the decrypted message
    }

    /**
     * Performs the AES key schedule core operation on a 4-byte word.
     * Shifts bytes, substitutes using the S-box, and XORs the first byte with RCON.
     *
     * @param word 4-byte word to transform
     * @param round the current round number
     * @return transformed 4-byte word
     */
    private byte[] keyScheduleCore(byte[] word, int round){
        // Shift the 4 bytes in the temporary location one byte to the left
        byte temp = word[0];
        word[0] = word[1];
        word[1] = word[2];
        word[2] = word[3];
        word[3] = temp;

        // Replace the 4 shifted bytes in the temporary location with their substitutions from the AES S-box
        for (int i = 0; i < 4; i++) {
            word[i] = (byte)S_BOX[word[i] & 0xFF]; // Normalize index to be between 0 and 255, inclusive.
        }

        // Only the first byte of the temporary location is XORed with the RCON value for the given round
        word[0] ^= (byte) RCON[round];

        return word;
    }

    /**
     * Expands a 16-byte AES key into all round keys.
     * Generates NUM_ROUNDS + 1 round keys for AES encryption.
     *
     * @param key the original 16-byte AES key
     * @return a 2D array of round keys, each 16 bytes
     */
    private byte[][] expandKey(byte[] key){
        byte[][] roundKeys = new byte[NUM_ROUNDS + 1][KEY_LENGTH]; // 11 round keys of 16 bytes
        byte[][] words = new byte[WORDS_IN_KEY * (NUM_ROUNDS + 1)][4]; // 44 words of length 4

        // Fill first 4 words with the original key
        for (int i = 0; i < WORDS_IN_KEY; i++) {
            System.arraycopy(key, i * 4, words[i], 0, 4);
        }

        for (int i = WORDS_IN_KEY; i < words.length; i++) {
            byte[] temp = words[i - 1].clone();

            // Take the last 4 bytes of the previous round key, store it in a temporary location, and run it through the key schedule core
            if (i % WORDS_IN_KEY == 0) {
                temp = keyScheduleCore(temp, i / WORDS_IN_KEY); // Divide by 4 to get the round number
            }

            //After the core, you XOR the data in the temporary location with the corresponding 4
            //bytes from the previous round key and store it in the temporary location
            for (int j = 0; j < 4; j++) {
                words[i][j] = (byte) (words[i - WORDS_IN_KEY][j] ^ temp[j]);
            }
        }

        // Combine every 4 words into a 16-byte round key
        for (int round = 0; round <= NUM_ROUNDS; round++) {
            for (int i = 0; i < WORDS_IN_KEY; i++) {
                System.arraycopy(words[round * WORDS_IN_KEY + i], 0, roundKeys[round], i * 4, 4);
            }
        }

        return roundKeys;
    }

    private void loadState(byte[] bytes, byte[][] matrix) {
        int i = 0;
        for (int col = 0; col < MATRIX_LEN; col++) {
            for (int row = 0; row < MATRIX_LEN; row++) {
                matrix[row][col] = bytes[i++];
            }
        }
    }

    private void addRoundKey(byte[][]matrix, byte[] roundKeys){
        // Initial Round: Add round key
        int count = 0;
        for (int col = 0; col < MATRIX_LEN; col++) {
            for (int row = 0; row < MATRIX_LEN; row++) {
                matrix[row][col] ^= roundKeys[count++];
            }
        }
    }

    /**
     * individual bytes in the matrix are substituted for other bytes using an S-box
     *
     * @param matrix the message
     * @param inverse a false we do the regular substitution and if true we do the inverse for decryption
     */
    private void substituteByte(byte[][] matrix, boolean inverse){
        int[] box = inverse ? I_S_BOX : S_BOX;

        for (int col = 0; col < MATRIX_LEN; col++) {
            for (int row = 0; row < MATRIX_LEN; row++) {
                matrix[row][col] = (byte) box[matrix[row][col] & 0xFF]; // Normalize index to be between 0 and 255, inclusive.
            }
        }
    }

    private void shiftRows(byte[][] matrix, boolean inverse){
        byte[] matrixRow = new byte[4];
        int sign = inverse ? -1 : 1; // If decrypting, subtract row otherwise add row

        for (int row = 1; row < MATRIX_LEN; row++) {
            for (int col = 0; col < MATRIX_LEN; col++)
                matrixRow[col] = matrix[row][col];

            for (int column = 0; column < MATRIX_LEN; column++)  // Shift rows left
                matrix[row][column] = matrixRow[(column + row * sign + MATRIX_LEN) % MATRIX_LEN];
        }
    }

    private static void inverseMixColumns(byte[][] state) {
        byte[] a = new byte[MATRIX_LEN];

        for (int j = 0; j < MATRIX_LEN; ++j) {
            for (int i = 0; i < MATRIX_LEN; ++i)
                a[i] = state[i][j];

            state[0][j] = (byte) (galoisMultiply(a[0],14) ^ galoisMultiply(a[3],9) ^ galoisMultiply(a[2],13) ^ galoisMultiply(a[1],11));
            state[1][j] = (byte) (galoisMultiply(a[1],14) ^ galoisMultiply(a[0],9) ^ galoisMultiply(a[3],13) ^ galoisMultiply(a[2],11));
            state[2][j] = (byte) (galoisMultiply(a[2],14) ^ galoisMultiply(a[1],9) ^ galoisMultiply(a[0],13) ^ galoisMultiply(a[3],11));
            state[3][j] = (byte) (galoisMultiply(a[3],14) ^ galoisMultiply(a[2],9) ^ galoisMultiply(a[1],13) ^ galoisMultiply(a[0],11));
        }
    }

    private static void mixColumns(byte[][]matrix){
        byte[][] mixColumnMatrix = {
                {(byte)0x02, (byte)0x03, (byte)0x01, (byte)0x01},
                {(byte)0x01, (byte)0x02, (byte)0x03, (byte)0x01},
                {(byte)0x01, (byte)0x01, (byte)0x02, (byte)0x03},
                {(byte)0x03, (byte)0x01, (byte)0x01, (byte)0x02}
        };
        byte[][] newMatrix = new byte[MATRIX_LEN][MATRIX_LEN];

        for(int i = 0; i<MATRIX_LEN; i++){ //moving over row in mix col matrix
            for(int j = 0 ; j<MATRIX_LEN; j++){ // moving over columns of matrix
                int sumOfRowCol = 0;
                for (int k = 0; k<MATRIX_LEN; k++){ //move colums of mixcolmatrix
                    int a = mixColumnMatrix[i][k]; //i,k is row col in mix col matrix
                    int b = matrix[k][j]; //gets value while moving columns in the original matrix
                    sumOfRowCol ^= galoisMultiply(a,b);
                    /*summing (apparently summing is done through xor) the product of
                     *columns of mixcolmatrix to row values of original matrix
                     */

                }
                //out of k loop
                newMatrix[i][j] = (byte) sumOfRowCol;
            }
        }
        for(int i = 0; i<MATRIX_LEN; i++){
            for (int j = 0; j<MATRIX_LEN; j++){
                matrix[i][j] = newMatrix[i][j];
            }
        }

    }

    /* code provided by prof wittman */
    private static byte galoisMultiply(int a, int b) {
        int p = 0;
        int highBit;

        for (int i = 0; i < 8; ++i) {
            if ((b & 1) == 1)
                p ^= a;
            highBit = a & 0x80;
            a <<= 1;
            if (highBit == 0x80)
                a ^= 0x1b;
            b >>= 1;
        }


        p &= 0xff;

        return (byte)p;
    }

    private byte[] extractMessage(byte[][] matrix) {
        // Extract message
        int count = 0;
        byte[] message = new byte[16];
        for (int col = 0; col < MATRIX_LEN; col++) {
            for (int row = 0; row < MATRIX_LEN; row++) {
                message[count++] = matrix[row][col];
            }
        }

        return message;
    }

}
