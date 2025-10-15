import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.Random;
import java.util.Scanner;

public class Chat {
    private Socket socket;
    private boolean client;
    private ObjectOutputStream netOut;
    private ObjectInputStream netIn;
    private Sender sender;
    private Receiver receiver;
    // Diffie-Hellman public parameters
    public static final BigInteger P = new BigInteger("150396459018121493735075635131373646237977288026821404984994763465102686660455819886399917636523660049699350363718764404398447335124832094110532711100861016024507364395416614225232899925070791132646368926029404477787316146244920422524801906553483223845626883475962886535263377830946785219701760352800897738687");
    public static final BigInteger G = new BigInteger("105003596169089394773278740673883282922302458450353634151991199816363405534040161825176553806702944696699090103171939463118920452576175890312021100994471453870037718208222180811650804379510819329594775775023182511986555583053247825364627124790486621568154018452705388790732042842238310957220975500918398046266");
    public static final int LENGTH = 1023;
    public static final int MATRIX_LEN = 4;
    private byte[] key = new byte[16];
    private int originalMessageLen;
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

    public static void main(String[] args) throws UnknownHostException, IOException {
        Scanner in = new Scanner(System.in);
        System.out.println("Welcome to Secure Chat");
        System.out.println();

        boolean valid = false;

        try {
            do {
                System.out.print("Client or server? Enter c or s: ");
                String choice = in.nextLine();
                char letter = choice.toLowerCase().charAt(0);
                int port;

                if (letter == 's') {
                    System.out.print("Enter port number: ");
                    port = in.nextInt();
                    System.out.println("Waiting for client...");
                    new Chat(port);
                    valid = true;
                } else if (letter == 'c') {
                    System.out.println("Be sure to start server first!");
                    System.out.print("Enter IP address: ");
                    String IP = in.next();
                    System.out.print("Enter port number: ");
                    port = in.nextInt();
                    new Chat(IP, port);
                    valid = true;
                } else {
                    System.out.println("Invalid choice.");
                }
            } while( !valid );
        } catch(InterruptedException | ClassNotFoundException e) {}
    }

    // Server
    public Chat(int port) throws IOException, InterruptedException, ClassNotFoundException {
        client = false;
        ServerSocket serverSocket = new ServerSocket(port);
        socket = serverSocket.accept();
        runChat();
    }

    // Client
    public Chat(String address, int port) throws UnknownHostException, IOException, InterruptedException, ClassNotFoundException {
        client = true;
        socket = new Socket(address, port);
        runChat();
    }

    public void runChat() throws InterruptedException, IOException, ClassNotFoundException {
        netOut = new ObjectOutputStream(socket.getOutputStream());
        netIn = new ObjectInputStream(socket.getInputStream());

        System.out.println("Running chat ...");
        System.out.println();

        // TODO: Negotiate key using Diffie-Hellman here
        BigInteger b = new BigInteger(LENGTH, new Random());
        BigInteger B = G.modPow(b, P);
        netOut.writeObject(B);
        netOut.flush();

        BigInteger AValue = (BigInteger) netIn.readObject();
        byte[] largeKey = AValue.modPow(b, P).toByteArray();
        System.arraycopy(largeKey, 0, key, 0, KEY_LENGTH); // Take only the first 16 bytes from original key
        System.out.println("Key: " + Arrays.toString(key));

        // Debug print
        System.out.println();
        byte[][] keys = expandKey(key);
        for (int i = 0; i < keys.length; i++) {
            System.out.println("Round " + i + " Key: " + Arrays.toString(keys[i]));
        }
        System.out.println();

        sender = new Sender();
        receiver = new Receiver();
        sender.start();
        receiver.start();
        sender.join();
        receiver.join();
    }

    private class Sender extends Thread {
        public void run() {
            try {
                Scanner in = new Scanner(System.in);
                System.out.print("Enter your name: ");
                String name = in.nextLine();
                String buffer = "";
                while (!socket.isClosed()) {
                    buffer = in.nextLine();
                    if (buffer.trim().toLowerCase().equals("quit")) {
                        return;
                    } else {
                        String line = name + ": " + buffer;
                        originalMessageLen = line.getBytes().length;

                        // Padding the message with 0s so it is a multiple of 16
                        byte[] bytes = padding();
                        System.arraycopy(line.getBytes(), 0, bytes, 0, originalMessageLen);

                        // TODO: Encrypt bytes here before sending them

                        netOut.writeObject(bytes);
                        netOut.flush();
                    }
                }
            } catch (IOException e) {
            } finally {
                try {
                    netOut.close();
                    netIn.close();
                    socket.close();
                } catch( IOException e ) {}
            }
        }
    }

    /**
     * Pads the input string to make its length a multiple of the AES block size (16 bytes).
     *
     * @return a byte array with zero-padding added as needed
     */
    private byte[] padding() {
        int padding = 0;

        if(originalMessageLen > KEY_LENGTH && originalMessageLen % KEY_LENGTH != 0)
            padding = KEY_LENGTH - originalMessageLen % KEY_LENGTH; // Number of 0's to add to message
        else if (originalMessageLen < KEY_LENGTH)
            padding = KEY_LENGTH - originalMessageLen; // Number of 0's to add to message if message is shorter than 16

        return new byte[originalMessageLen + padding];
    }

    /**
     * Encrypts a 16-byte plaintext block using AES-128.
     * Performs key expansion, initial AddRoundKey, 9 normal rounds
     * (Substitute Bytes, Shift Rows, Mix Columns, Add Round Key), and the final round.
     *
     * @param bytes 16-byte plaintext block
     * @return 16-byte ciphertext block
     */
    private byte[] AESEncryption(byte[] bytes){
        byte[][] matrix = new byte[MATRIX_LEN][MATRIX_LEN]; //every 16 bytes of message
        byte[][] roundKeys = expandKey(key);

        // Load data into state matrix
        for (byte aByte : bytes) {
            for (int col = 0; col < MATRIX_LEN; col++) {
                for (int row = 0; row < MATRIX_LEN; row++) {
                    matrix[row][col] = aByte;
                }
            }
        }

        // Initial Round: Add round key
        addRoundKey(matrix, roundKeys[0]);

        // Normal rounds (1-9)
        for (int round = 1; round < NUM_ROUNDS; round++) {

            // Substitute bytes
            substituteByte(matrix);

            // Shift rows here
            shiftRows(matrix);

            // TODO: Mix columns here


            // Add Round Key
            addRoundKey(matrix, roundKeys[round]);
        }

        // Final round (10)

        // Substitute bytes
        substituteByte(matrix);

        // Shift rows here
        shiftRows(matrix);

        // AddRoundKey
        addRoundKey(matrix, roundKeys[NUM_ROUNDS]);

        // Extract ciphertext
        int count = 0;
        byte[] ciphertext = new byte[16];
        for (int col = 0; col < MATRIX_LEN; col++) {
            for (int row = 0; row < MATRIX_LEN; row++) {
                ciphertext[count++] = matrix[col][row];
            }
        }

        return ciphertext;
    }

    /**
     * Expands a 16-byte AES key into all round keys.
     * Generates NUM_ROUNDS + 1 round keys for AES encryption.
     *
     * @param key the original 16-byte AES key
     * @return a 2D array of round keys, each 16 bytes
     */

    //talk to sam about this
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

    private class Receiver extends Thread {
        public void run() {
            try {
                while (!socket.isClosed()) {
                    byte[] bytes = (byte[])(netIn.readObject());
                    // TODO: Decrypt bytes here before reconstituting String
                    String line = new String(bytes);
                    System.out.println(line);
                }
            } catch (IOException e) {
            } catch (ClassNotFoundException e) { // Should never happen
                e.printStackTrace();
            } finally {
                try {
                    netOut.close();
                    netIn.close();
                    socket.close();
                } catch( IOException e ) {}
                System.out.print("Connection closed.");
                // Bad programming style that would be unnecessary if this chat were in a GUI:
                System.exit(0);
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

    private void substituteByte(byte[][] matrix){
        for (int col = 0; col < MATRIX_LEN; col++) {
            for (int row = 0; row < MATRIX_LEN; row++) {
                matrix[row][col] = (byte) S_BOX[matrix[row][col] & 0xFF]; // Normalize index to be between 0 and 255, inclusive.
            }
        }
    }
  
    private void shiftRows(byte[][] matrix){
            byte[] matrixRow = new byte[4];

            for(int row = 1; row < MATRIX_LEN; row++) {
                    for(int column = 0; column<MATRIX_LEN; column++){
                        matrixRow[column] = matrix[row][column];
                    }
                    for(int column = 0; column<MATRIX_LEN; column++){
                        matrix[row][column] = matrixRow[(column+row)%MATRIX_LEN];
                    }
            }

    }
}
