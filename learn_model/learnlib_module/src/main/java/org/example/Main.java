package org.example;

import java.io.IOException;

// Main function
public class Main {
    // Configuration file relative path
    static final String confPath = "src/main/resources/conf.properties";

    public static void main(String[] args) throws IOException {

        // Load Configuration
        LearnConfiguration conf = new LearnConfiguration(confPath);

        // Building Sockets for Communication
        NetworkManager network = new NetworkManager(conf);

        // Get Alphabet
        if (conf.setAlphabet()) {
            // Build a learner
            Learner learner= new Learner(conf, network);
            // learn state machine
            learner.learn();
        }
    }
}