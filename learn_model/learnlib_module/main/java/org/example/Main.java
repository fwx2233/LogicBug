package org.example;

import java.io.IOException;
import java.util.Objects;
import java.util.Scanner;

// Main function
public class Main {
    // Configuration file relative path
    static final String confPath = "src/main/resources/conf.properties";

    public static void main(String[] args) throws IOException {

        // Load Configuration
        LearnConfiguration conf = new LearnConfiguration(confPath);

        // Building Sockets for Communication
        NetworkManager network = new NetworkManager(conf);

        // Set cache query
        CacheManager cache = new CacheManager();

        // Get Alphabet
        if (conf.setAlphabet()) {
            // Build a learner
            Learner learner= new Learner(conf, network, cache);
            // learn state machine
            learner.learn();
        }
    }
}