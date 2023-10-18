package org.example;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Arrays;

public class NetworkManager {
    ServerSocket serverSocket;
    Socket clientSocket;
    OutputStream out;
    InputStream in;
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

    public String sendQuery(String query) throws IOException {
        return new String(sendMessage(1, query));
    }

    private void sendAlphabetRequest() throws IOException {
        sendMessage(0, "alphabet");
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

        if (type == 0)
            LogManager.logger.logEvent("Sent successfully!");

        return receiveMessage(type);
    }

    private byte[] receiveMessage(int type) throws IOException {
        // Read byte array
        byte[] receiveMessage = new byte[1024];
        int bytesReceive = in.read(receiveMessage);

        byte receiveType = receiveMessage[0];
        byte[] messageBytes = new byte[bytesReceive - 1];
        System.arraycopy(receiveMessage, 1, messageBytes, 0, bytesReceive - 1);
        String message = new String(messageBytes);//LogManager.logger.logEvent(message);

        if (type == 0 && (int)receiveType == 0) {
            // TODO 当消息发送和接收类型都与字符表相关，对字符串进行判断
            if (message.equals("Succeed!")) {
                LogManager.logger.logEvent(message);
            }
        } else if (type == 1) {
            LogManager.logger.logEvent("Response: " + message);
        }

        return messageBytes;
    }
}
