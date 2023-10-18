package org.example;
import java.io.*;
import java.net.*;
import java.util.Arrays;

public class Test {
    public static void main(String[] args) {
        try {
            // 创建一个 Socket 并连接到服务器端的 IP 地址和端口号
            Socket socket = new Socket("localhost", 9999);


            OutputStream out = socket.getOutputStream();
            InputStream in = socket.getInputStream();

            // 创建输入流来读取客户端用户输入
            BufferedReader clientReader = new BufferedReader(new InputStreamReader(System.in));

            // 循环进行交互
            while (true) {
                // 从服务器读取响应
                byte[] receiveMessage = new byte[1024];
                int bytesReceive = in.read(receiveMessage);
                System.out.println("服务器响应: " + Arrays.toString(receiveMessage));

                byte receiveType = receiveMessage[0];
                byte[] messageBytes = new byte[bytesReceive - 1];
                System.arraycopy(receiveMessage, 1, messageBytes, 0, bytesReceive - 1);
                String message = new String(messageBytes);

                System.out.println("ReceiveType: " + receiveType);
                System.out.println("Message: " + message);
                if (message.equals("Exit"))
                    break;

                // 从客户端读取用户输入并发送给服务器端
                String clientMessage = clientReader.readLine();
                messageBytes = clientMessage.getBytes();
                byte[] totalBytes = new byte[1 + messageBytes.length];
                totalBytes[0] = receiveType;
                System.out.println("TotalBytes: " + Arrays.toString(totalBytes));
                System.arraycopy(messageBytes, 0, totalBytes, 1, messageBytes.length);
                System.out.println("TotalBytes: " + Arrays.toString(totalBytes));
                out.write(totalBytes);
            }

            // 关闭连接
            in.close();
            out.close();
            socket.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}