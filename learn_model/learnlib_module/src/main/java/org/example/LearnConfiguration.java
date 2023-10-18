package org.example;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Properties;

public class LearnConfiguration {
    Properties properties;

    String proName = "IoTLearner";
    String host = "127.0.0.1";
    int port = 9999;
    String outputDir = "result";
    String alphabetFile = "src/main/resources/input_bat";
    AlphabetManager aM;

    // Build Properties object to read configuration information
    public LearnConfiguration(String confPath) throws IOException {
        properties = new Properties();
        InputStream input = Files.newInputStream(Paths.get(confPath));
        properties.load(input);
        loadProperties();
    }

    // Load configuration information, or use the default configuration
    private void loadProperties() {
        // Project Name
        if(properties.getProperty("proName") != null)
            proName = properties.getProperty("proName");
        else {
            LogManager.logger.logEvent("Null project name");
        }
        LogManager.resetName(proName);
        LogManager.logger.logEvent("The project name: " + proName);

        // Host
        if(properties.getProperty("host") != null)
            host = properties.getProperty("host");
        else
            LogManager.logger.logEvent("Null host");
        LogManager.logger.logEvent("The host: " + host);

        // Port
        if(properties.getProperty("port") != null)
            port = Integer.parseInt(properties.getProperty("port"));
        else
            LogManager.logger.logEvent("Null port");
        LogManager.logger.logEvent("The port: " + port);

        // Output Directory
        if(properties.getProperty("outputDir") != null)
            outputDir = properties.getProperty("outputDir");
        else
            LogManager.logger.logEvent("Null output directory");
        LogManager.logger.logEvent("The output directory: " + outputDir);

        // Alphabet File
        if(properties.getProperty("alphabetFile") != null)
            alphabetFile = properties.getProperty("alphabetFile");
        else
            LogManager.logger.logEvent("Null alphabet file");
        LogManager.logger.logEvent("The alphabet file: " + alphabetFile);

        // TODO 完善其他配置参数的载入

        LogManager.logger.logEvent("Loading configuration succeeds");
    }

    public boolean setAlphabet() {
        File file = new File(alphabetFile);

        if (file.exists()) {
            aM = new AlphabetManager(alphabetFile);
            return true;
        } else {
            LogManager.logger.logEvent("The alphabet file hasn't existed");
            return false;
        }
    }
}
