package org.example;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

public class NetworkManager {
    protected static final int SYSTEM_MESSAGE = 0;
    protected static final int LEARNLIB_MESSAGE = 1;
    protected static final int QUERY_MESSAGE = 2;
    private ServerSocket serverSocket;
    private Socket clientSocket;
    private OutputStream out;
    private InputStream in;
    public NetworkManager(LearnConfiguration conf) throws IOException {
        try {
            serverSocket = new ServerSocket(conf.port);
            LogManager.logger.logEvent("Waiting for the client to connect....");
            clientSocket = serverSocket.accept();

        } catch (Exception e) {
            LogManager.logger.logEvent("Client did not connect successfully");
            return;
        }
        clientSocket.setTcpNoDelay(true);
        clientSocket.setSoTimeout(0);
        out = clientSocket.getOutputStream();
        in = clientSocket.getInputStream();

        LogManager.logger.logEvent("Client Connected");

        // Send a request message to receive an alphabet file
        sendAlphabetRequest();
    }

    public String sendQuery(int type, String query) throws IOException {
        return new String(sendMessage(type, query));
    }

    private void sendAlphabetRequest() throws IOException {
        sendMessage(SYSTEM_MESSAGE, "alphabet");
    }

    private byte[] sendMessage(int type, String message) throws IOException {
        byte[] typeByte = {(byte)type};
        byte[] messageBytes = message.getBytes();

        // Splice
        byte[] totalBytes = new byte[typeByte.length + messageBytes.length];
        System.arraycopy(typeByte, 0, totalBytes, 0, typeByte.length);
        System.arraycopy(messageBytes, 0, totalBytes, typeByte.length, messageBytes.length);

        // Send message to client
        out.write(totalBytes);
//        LogManager.logger.logEvent(Arrays.toString(totalBytes));

        if (type == SYSTEM_MESSAGE)
            LogManager.logger.logEvent("Sent system message (" + message + ") successfully!");

        return receiveMessage(type);
    }

    private byte[] receiveMessage(int type) throws IOException {
        // Read byte array
        byte[] receiveMessage = new byte[1024];
        int bytesReceive = in.read(receiveMessage);

        byte receiveType = receiveMessage[0];
        byte[] messageBytes = new byte[bytesReceive - 1];
        System.arraycopy(receiveMessage, 1, messageBytes, 0, bytesReceive - 1);
        String message = new String(messageBytes);

        // Process the message
        if (receiveType > type) {
            LogManager.logger.logEvent("Receive lower type message");
            return "stop".getBytes();
        }
        switch (receiveType) {
            case SYSTEM_MESSAGE:
                LogManager.logger.logSystem(message);
                break;
            case LEARNLIB_MESSAGE:
            case QUERY_MESSAGE:
                LogManager.logger.logQuery(message);
                break;
            default:
                LogManager.logger.logEvent("Wrong type message");
        }

        return messageBytes;
    }

    public List<String> checkCounterExample(List<String> symbols) throws IOException {
        sendMessage(LEARNLIB_MESSAGE, "checkCounterExample");
        List<String> result = new ArrayList<>();
        System.out.println("symbols: " + symbols);
        System.out.println("result: " + result);
        for (String symbol : symbols) {
            if (Objects.equals(symbol, "Reset")) {
                result.add(sendQuery(LEARNLIB_MESSAGE, symbol));
            }
            else {
                result.add(sendQuery(QUERY_MESSAGE, symbol));
            }
        }
        LogManager.logger.logQuery(result.toString());
        return result;
    }

    public void closeConnection() throws IOException {
        sendMessage(SYSTEM_MESSAGE, "closeConnect");
        clientSocket.close();
        LogManager.logger.logEvent("Close the connection");
    }

}
