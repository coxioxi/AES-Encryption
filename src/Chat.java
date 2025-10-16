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
    private byte[] key = new byte[16];
    private int originalMessageLen;
    private static final int KEY_LENGTH = 16;


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

        /* Debug print
        System.out.println();
        byte[][] keys = expandKey(key);
        for (int i = 0; i < keys.length; i++) {
            System.out.println("Round " + i + " Key: " + Arrays.toString(keys[i]));
        }
        System.out.println();
        */
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
