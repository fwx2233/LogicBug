package org.example;

import java.util.*;

public class Test {
    private String getWinner(String... votes) {
        Map<String, Integer> voteCount = new HashMap<>();

        for (String vote : votes) {
            voteCount.put(vote, voteCount.getOrDefault(vote, 0) + 1);
        }

        String winner = null;
        int maxVotes = 0;

        for (Map.Entry<String, Integer> entry : voteCount.entrySet()) {
            if (entry.getValue() > maxVotes) {
                maxVotes = entry.getValue();
                winner = entry.getKey();
            }
        }

        return winner;
    }

    private List<String> processVotes(List<List<String>> votes) {
        int n = votes.get(0).size();
        List<String> result = new ArrayList<>();

        for (int i = 0; i < n; i++) {
            String vote1 = votes.get(0).get(i);
            String vote2 = votes.get(1).get(i);
            String vote3 = votes.get(2).get(i);
            String vote4 = votes.get(3).get(i);

            String winner = getWinner(vote1, vote2, vote3, vote4);
            result.add(winner);
        }

        return result;
    }
    public static void main(String[] args) {
        List<String> list1 = Arrays.asList("Reset_suc", "ADU1CWR_CLS_15", "DCU1_CLS_-1", "NoElement");
        List<String> list2 = Arrays.asList("Reset_suc", "ADU1CWR_CLS_-1", "DCU1_CLS_8", "NoElement");
        List<String> list3 = Arrays.asList("Reset_suc", "ADU1CWR_CLS_16", "DCU1_CLS_9", "NoElement");
        List<String> list4 = Arrays.asList("Reset_suc", "ADU1CWR_CLS_-1", "DCU1_CLS_-1", "NoElement");

        List<List<String>> results = new ArrayList<>();

        results.add(list1);
        results.add(list2);
        results.add(list3);
        results.add(list4);

        System.out.println("Result List: " + results);

        Test test = new Test();

        List<String> result = test.processVotes(results);

        System.out.println("Result: " + result);


//        CacheManager dataStorage  = new CacheManager();
//        // 添加数据对
//        dataStorage.add("A", "123");
//        dataStorage.add("B", "456");
//        dataStorage.add("C", "789");
//
//        // 将数据写入目标文件并清空数据结构
//        dataStorage.writeCache();
//        // 添加数据对
//        dataStorage.add("A", "123");
//        dataStorage.add("B", "456");
//        dataStorage.add("C", "789");
//        dataStorage.writeCache();
//        dataStorage.add("A", "123");
//        dataStorage.add("B", "456");
//        dataStorage.add("C", "789");

//       try {
//            // 创建一个 Socket 并连接到服务器端的 IP 地址和端口号
//            Socket socket = new Socket("localhost", 9999);
//
//
//            OutputStream out = socket.getOutputStream();
//            InputStream in = socket.getInputStream();
//
//            // 创建输入流来读取客户端用户输入
//            BufferedReader clientReader = new BufferedReader(new InputStreamReader(System.in));
//
//            // 循环进行交互
//            while (true) {
//                // 从服务器读取响应
//                byte[] receiveMessage = new byte[1024];
//                int bytesReceive = in.read(receiveMessage);
//                System.out.println("服务器响应: " + Arrays.toString(receiveMessage));
//
//                byte receiveType = receiveMessage[0];
//                byte[] messageBytes = new byte[bytesReceive - 1];
//                System.arraycopy(receiveMessage, 1, messageBytes, 0, bytesReceive - 1);
//                String message = new String(messageBytes);
//
//                System.out.println("ReceiveType: " + receiveType);
//                System.out.println("Message: " + message);
//                if (message.equals("Exit"))
//                    break;
//
//                 // 从客户端读取用户输入并发送给服务器端
//                String clientMessage = clientReader.readLine();
//                messageBytes = clientMessage.getBytes();
//                byte[] totalBytes = new byte[1 + messageBytes.length];
//                totalBytes[0] = receiveType;
//                System.out.println("TotalBytes: " + Arrays.toString(totalBytes));
//                System.arraycopy(messageBytes, 0, totalBytes, 1, messageBytes.length);
//                System.out.println("TotalBytes: " + Arrays.toString(totalBytes));
//                out.write(totalBytes);
//            }
//
//            // 关闭连接
//            in.close();
//            out.close();
//            socket.close();
//        } catch (IOException e) {
//            e.printStackTrace();
//        }
    }
}