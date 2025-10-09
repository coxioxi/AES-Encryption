import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.UnknownHostException;
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

    private static final byte[] RCON = {
            (byte)0x8d, (byte)0x01, (byte)0x02, (byte)0x04, (byte)0x08, (byte)0x10,
            (byte)0x20, (byte)0x40, (byte)0x80, (byte)0x1b, (byte)0x36, (byte)0x6c,
            (byte)0xd8, (byte)0xab, (byte)0x4d, (byte)0x9a, (byte)0x2f, (byte)0x5e,
            (byte)0xbc, (byte)0x63, (byte)0xc6, (byte)0x97, (byte)0x35, (byte)0x6a,
            (byte)0xd4, (byte)0xb3, (byte)0x7d, (byte)0xfa, (byte)0xef, (byte)0xc5,
            (byte)0x91, (byte)0x39, (byte)0x72, (byte)0xe4, (byte)0xd3, (byte)0xbd,
            (byte)0x61, (byte)0xc2, (byte)0x9f, (byte)0x25, (byte)0x4a, (byte)0x94,
            (byte)0x33, (byte)0x66, (byte)0xcc, (byte)0x83, (byte)0x1d, (byte)0x3a,
            (byte)0x74, (byte)0xe8, (byte)0xcb
    };

    private static final byte[] S_BOX = {
            (byte)0x63,(byte)0x7c,(byte)0x77,(byte)0x7b,(byte)0xf2,(byte)0x6b,(byte)0x6f,(byte)0xc5,
            (byte)0x30,(byte)0x01,(byte)0x67,(byte)0x2b,(byte)0xfe,(byte)0xd7,(byte)0xab,(byte)0x76,
            (byte)0xca,(byte)0x82,(byte)0xc9,(byte)0x7d,(byte)0xfa,(byte)0x59,(byte)0x47,(byte)0xf0,
            (byte)0xad,(byte)0xd4,(byte)0xa2,(byte)0xaf,(byte)0x9c,(byte)0xa4,(byte)0x72,(byte)0xc0,
            (byte)0xb7,(byte)0xfd,(byte)0x93,(byte)0x26,(byte)0x36,(byte)0x3f,(byte)0xf7,(byte)0xcc,
            (byte)0x34,(byte)0xa5,(byte)0xe5,(byte)0xf1,(byte)0x71,(byte)0xd8,(byte)0x31,(byte)0x15,
            (byte)0x04,(byte)0xc7,(byte)0x23,(byte)0xc3,(byte)0x18,(byte)0x96,(byte)0x05,(byte)0x9a,
            (byte)0x07,(byte)0x12,(byte)0x80,(byte)0xe2,(byte)0xeb,(byte)0x27,(byte)0xb2,(byte)0x75,
            (byte)0x09,(byte)0x83,(byte)0x2c,(byte)0x1a,(byte)0x1b,(byte)0x6e,(byte)0x5a,(byte)0xa0,
            (byte)0x52,(byte)0x3b,(byte)0xd6,(byte)0xb3,(byte)0x29,(byte)0xe3,(byte)0x2f,(byte)0x84,
            (byte)0x53,(byte)0xd1,(byte)0x00,(byte)0xed,(byte)0x20,(byte)0xfc,(byte)0xb1,(byte)0x5b,
            (byte)0x6a,(byte)0xcb,(byte)0xbe,(byte)0x39,(byte)0x4a,(byte)0x4c,(byte)0x58,(byte)0xcf,
            (byte)0xd0,(byte)0xef,(byte)0xaa,(byte)0xfb,(byte)0x43,(byte)0x4d,(byte)0x33,(byte)0x85,
            (byte)0x45,(byte)0xf9,(byte)0x02,(byte)0x7f,(byte)0x50,(byte)0x3c,(byte)0x9f,(byte)0xa8,
            (byte)0x51,(byte)0xa3,(byte)0x40,(byte)0x8f,(byte)0x92,(byte)0x9d,(byte)0x38,(byte)0xf5,
            (byte)0xbc,(byte)0xb6,(byte)0xda,(byte)0x21,(byte)0x10,(byte)0xff,(byte)0xf3,(byte)0xd2,
            (byte)0xcd,(byte)0x0c,(byte)0x13,(byte)0xec,(byte)0x5f,(byte)0x97,(byte)0x44,(byte)0x17,
            (byte)0xc4,(byte)0xa7,(byte)0x7e,(byte)0x3d,(byte)0x64,(byte)0x5d,(byte)0x19,(byte)0x73,
            (byte)0x60,(byte)0x81,(byte)0x4f,(byte)0xdc,(byte)0x22,(byte)0x2a,(byte)0x90,(byte)0x88,
            (byte)0x46,(byte)0xee,(byte)0xb8,(byte)0x14,(byte)0xde,(byte)0x5e,(byte)0x0b,(byte)0xdb,
            (byte)0xe0,(byte)0x32,(byte)0x3a,(byte)0x0a,(byte)0x49,(byte)0x06,(byte)0x24,(byte)0x5c,
            (byte)0xc2,(byte)0xd3,(byte)0xac,(byte)0x62,(byte)0x91,(byte)0x95,(byte)0xe4,(byte)0x79,
            (byte)0xe7,(byte)0xc8,(byte)0x37,(byte)0x6d,(byte)0x8d,(byte)0xd5,(byte)0x4e,(byte)0xa9,
            (byte)0x6c,(byte)0x56,(byte)0xf4,(byte)0xea,(byte)0x65,(byte)0x7a,(byte)0xae,(byte)0x08,
            (byte)0xba,(byte)0x78,(byte)0x25,(byte)0x2e,(byte)0x1c,(byte)0xa6,(byte)0xb4,(byte)0xc6,
            (byte)0xe8,(byte)0xdd,(byte)0x74,(byte)0x1f,(byte)0x4b,(byte)0xbd,(byte)0x8b,(byte)0x8a,
            (byte)0x70,(byte)0x3e,(byte)0xb5,(byte)0x66,(byte)0x48,(byte)0x03,(byte)0xf6,(byte)0x0e,
            (byte)0x61,(byte)0x35,(byte)0x57,(byte)0xb9,(byte)0x86,(byte)0xc1,(byte)0x1d,(byte)0x9e,
            (byte)0xe1,(byte)0xf8,(byte)0x98,(byte)0x11,(byte)0x69,(byte)0xd9,(byte)0x8e,(byte)0x94,
            (byte)0x9b,(byte)0x1e,(byte)0x87,(byte)0xe9,(byte)0xce,(byte)0x55,(byte)0x28,(byte)0xdf,
            (byte)0x8c,(byte)0xa1,(byte)0x89,(byte)0x0d,(byte)0xbf,(byte)0xe6,(byte)0x42,(byte)0x68,
            (byte)0x41,(byte)0x99,(byte)0x2d,(byte)0x0f,(byte)0xb0,(byte)0x54,(byte)0xbb,(byte)0x16
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
        System.arraycopy(largeKey, 0, key, 0, KEY_LENGTH); // Take only the first 16 bits from original key

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
                        int padding = 0;
                        if(line.getBytes().length % KEY_LENGTH != 0){
                            padding = KEY_LENGTH - line.getBytes().length % KEY_LENGTH; // Number of 0's to add to message
                        }
                        byte[] bytes = new byte[line.getBytes().length + padding];
                        System.arraycopy(line.getBytes(), 0, bytes, 0, line.getBytes().length);

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
     * Encrypts a 16-byte plaintext block using AES-128.
     * Performs key expansion, initial AddRoundKey, 9 normal rounds
     * (Substitute Bytes, Shift Rows, Mix Columns, Add Round Key), and the final round.
     *
     * @param bytes 16-byte plaintext block
     * @return 16-byte ciphertext block
     */
    private byte[] AESEncryption(byte[] bytes){
        byte[][] matrix = new byte[MATRIX_LEN][MATRIX_LEN];
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
        int count = 0;
        for (int col = 0; col < MATRIX_LEN; col++) {
            for (int row = 0; row < MATRIX_LEN; row++) {
                matrix[col][row] ^= roundKeys[0][count++];
            }
        }

        // Normal rounds (1-9)
        for (int round = 1; round <= NUM_ROUNDS; round++) {

            // Substitute bytes
            for (int col = 0; col < MATRIX_LEN; col++) {
                for (int row = 0; row < MATRIX_LEN; row++) {
                    matrix[col][row] = S_BOX[matrix[col][row] & 0xFF]; // Normalize index to be between 0 and 255, inclusive.
                }
            }

            // TODO: Shift rows here

            // TODO: Mix columns here

            // Add Round Key
            count = 0;
            for (int col = 0; col < MATRIX_LEN; col++) {
                for (int row = 0; row < MATRIX_LEN; row++) {
                    matrix[col][row] ^= roundKeys[round][count++];
                }
            }
        }

        // Final round (10)

        // TODO: Substitute bytes

        // TODO: Shift rows here

        // AddRoundKey
        count = 0;
        for (int col = 0; col < MATRIX_LEN; col++) {
            for (int row = 0; row < MATRIX_LEN; row++) {
                matrix[col][row] ^= roundKeys[NUM_ROUNDS][count++];
            }
        }

        // Extract ciphertext
        count = 0;
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
     * Generates NUM_ROUNDS + 1 round keys (16 bytes each) for AES encryption.
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
            word[i] = S_BOX[word[i] & 0xFF]; // Normalize index to be between 0 and 255, inclusive.
        }

        // Only the first byte of the temporary location is XORed with the RCON value for the given round
        word[0] ^= RCON[round];

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
}