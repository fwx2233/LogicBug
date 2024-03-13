package org.example;

import java.io.*;
import java.util.*;

public class CacheManager {
    static final String cachePath = "result/cache.txt";

    private final List<String> symbol;
    private final List<String> result;
    int index = 1;
    int resetNum = 0;

    public List<String> getSymbol() {
        return symbol;
    }

    public List<String> getResult() {
        return result;
    }

    public int getResetNum() {
        return resetNum;
    }
    public CacheManager() {
        System.out.println("CacheManager");
        resetNum = loadCache();
        System.out.println("resetNum: " + resetNum);
        this.symbol = new ArrayList<>();
        this.result = new ArrayList<>();
    }

    private void addReset() {
        symbol.add("Reset");
        result.add("Reset_suc");
        resetNum++;
    }

    private int loadCache() {
        System.out.println("load");
        // 计数器
        int resetLineCount = 0;

        try (BufferedReader reader = new BufferedReader(new FileReader(cachePath))) {
            String line;

            // 逐行读取文件内容
            while ((line = reader.readLine()) != null) {
                // 检查是否以 "Reset" 开头
                if (line.startsWith("Reset")) {
                    resetLineCount++;
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        return resetLineCount;
    }

    public void add(String symbol, String result) {
        System.out.println("add");
        // 存储数据对
        this.symbol.add(symbol);
        this.result.add(result);
        System.out.println("symbol: " + symbol);
        System.out.println("result: " + result);
    }

    public void writeCache(boolean isConflict) {
//        System.out.println("write");
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(cachePath, true))) {
            // 将数据写入目标文件
            for (int i = 0; i < Math.min(this.symbol.size(), this.result.size()); i++) {
                String line = this.symbol.get(i) + "," + this.result.get(i);
                writer.write(line);
                writer.newLine();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }

        // 清空数据结构
        this.symbol.clear();
        this.result.clear();
        if (!isConflict) {
            addReset();
            System.out.println("symbol: " + "Reset");
            System.out.println("result: " + "Reset_suc");
        }
    }

//    public void writeCacheForConflict() {
//        System.out.println("write(log)");
//        try (BufferedWriter writer = new BufferedWriter(new FileWriter(cachePath, true))) {
//            // 将数据写入目标文件
//            writer.write("[LOG] " + log);
//            writer.newLine();
//        } catch (IOException e) {
//            e.printStackTrace();
//        }
//
//    }

    public static String readLine(int lineNumber) {
        System.out.println("readLine");
        try (BufferedReader reader = new BufferedReader(new FileReader(cachePath))) {
            String line;
            int currentLine = 0;

            while ((line = reader.readLine()) != null) {
                currentLine++;

                if (currentLine == lineNumber) {
                    // 找到指定行
                    return line;
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }

        // 未找到指定行
        return null;
    }

    public boolean check() {
        System.out.println("check");
        String result;
        do {
            System.out.println("index: " + index);
            result = readLine(index++);
            System.out.println("result: " + result);
            System.out.println("index: " + index);

            if (result == null)
                return false;
        } while (result.startsWith("[LOG]"));
        return Objects.equals(result, "Reset,Reset_suc");
    }

    public String get(String symbol) {
        System.out.println("get");
        String result;
        do {
            System.out.println("index: " + index);
            result = readLine(index++);
            System.out.println("result: " + result);
            System.out.println("index: " + index);

            if (result == null)
                return "Wrong_null";
        } while (result.startsWith("Reset"));
        System.out.println("result: " + result);
        if (result.startsWith(symbol)) {
            return result.substring(symbol.length() + 1);
        }
        return "Wrong";
    }

    public void reloadCache() {
        System.out.println("reloadCache");
        resetNum -= 1;
        // ToDo Record the wrong cache

        this.symbol.clear();
        this.result.clear();

        System.out.println("symbol: " + "Reset");
        System.out.println("result: " + "Reset_suc");
    }

    public void reloadCache(List<String> symbol, List<String> result) {
        System.out.println("reloadCache aaa");

        System.out.println("result: " + this.result);
        System.out.println("symbol: " + this.symbol);
        this.result.clear();
        this.symbol.clear();
        System.out.println("result: " + result);
        System.out.println("symbol: " + symbol);

        this.result.addAll(result);

        this.symbol.addAll(symbol);
        System.out.println("result: " + this.result);

        System.out.println("symbol: " + this.symbol);

        writeCache(true);
        resetNum++;

    }
}
