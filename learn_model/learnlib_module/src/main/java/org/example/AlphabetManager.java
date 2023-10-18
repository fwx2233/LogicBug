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
            BufferedReader reader = new BufferedReader(new FileReader(alphabetFile));
            String alphabet;
            while ((alphabet = reader.readLine()) != null) {
                words.add(alphabet);
            }
            reader.close();
        } catch (IOException e) {
            LogManager.logger.logEvent(String.valueOf(e));
        }

        LogManager.logger.logEvent("Alphabets: " + words);
    }
}
