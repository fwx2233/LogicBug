package org.example;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class AlphabetManager {
    List<String> words;
    public AlphabetManager(String alphabetFile) {
        words = new ArrayList<>();

        try {
            // 创建一个BufferedReader来读取文件
            BufferedReader reader = new BufferedReader(new FileReader(alphabetFile));

            String alphabet;

            // 逐行读取文件内容并存入List
            while ((alphabet = reader.readLine()) != null) {
                words.add(alphabet);
            }

            // 关闭文件读取器
            reader.close();
        } catch (IOException e) {
            LogManager.logger.logEvent(String.valueOf(e));
        }

        LogManager.logger.logEvent("Alphabets: " + words);
    }
}
