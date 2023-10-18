package org.example;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;

public class NetworkManager {
    ServerSocket serverSocket;
    Socket clientSocket;
    OutputStream out;
    InputStream in;
    static int TYPE_LENGTH = 1;
    static int SYSTEM_MESSAGE = 0;
    static int LEARNLIB_MESSAGE = 1;
    static int QUERY_MESSAGE = 2;
    static int MESSAGE_BYTE = 32;
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

    private void sendAlphabetRequest() throws IOException {
        sendMessage(SYSTEM_MESSAGE, "Alphabet request");
    }

    public void sendLearnLibMessage(String content) throws IOException {
        sendMessage(LEARNLIB_MESSAGE, content);
    }

    public String sendQuery(String query) throws IOException {
        return new String(sendMessage(QUERY_MESSAGE, query));
    }

    private byte[] sendMessage(int type, String message) throws IOException {
        byte[] typeByte = {(byte)type};
        byte[] messageBytes = message.getBytes();

        // Splice
        byte[] totalBytes = new byte[TYPE_LENGTH + messageBytes.length];
        System.arraycopy(typeByte, 0, totalBytes, 0, TYPE_LENGTH);
        System.arraycopy(messageBytes, 0, totalBytes, TYPE_LENGTH, messageBytes.length);

        // Send message to client
        out.write(totalBytes);
        LogManager.logger.logEvent("Message: " + message);

        if (type == 0)
            LogManager.logger.logEvent("Sent successfully!");

        return receiveMessage(type);
    }

    private byte[] receiveMessage(int sendMessageType) throws IOException {
        // Read byte array
        byte[] receiveMessage = new byte[MESSAGE_BYTE];
        int bytesReceive = in.read(receiveMessage);

        byte receiveMessageType = receiveMessage[0];
        int bytesContent = bytesReceive - TYPE_LENGTH;
        byte[] contentBytes = new byte[bytesContent];
        System.arraycopy(receiveMessage, TYPE_LENGTH, contentBytes, 0, bytesContent);
        String message = new String(contentBytes);

        if (sendMessageType == SYSTEM_MESSAGE && (int)receiveMessageType == sendMessageType) {
            if (message.equals("Load successfully!")) {
                LogManager.logger.logEvent("System message: " + message);
            } else {
                LogManager.logger.logEvent("Other system message: " + message);
            }
        } else if (sendMessageType == LEARNLIB_MESSAGE && (int)receiveMessageType == sendMessageType) {
            LogManager.logger.logEvent("LearnLib message: " + message);
        } else if (sendMessageType == QUERY_MESSAGE && (int)receiveMessageType == sendMessageType) {
            LogManager.logger.logEvent("Response: " + message);
        } else {
            LogManager.logger.logEvent("Unexpected response: " + message);
        }

        return contentBytes;
    }
}
