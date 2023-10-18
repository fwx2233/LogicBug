package org.example;

import de.learnlib.api.SUL;
import net.automatalib.words.impl.GrowingMapAlphabet;

public class IoTSUL implements SUL<String, String> {
    GrowingMapAlphabet<String> alphabet;
    NetworkManager network;
    public IoTSUL(LearnConfiguration config, NetworkManager network) {
        // TODO 初始化 SUL
        alphabet = new GrowingMapAlphabet<>(config.aM.words);
        this.network = network;
    }

    public GrowingMapAlphabet<String> getAlphabet() {
        return alphabet;
    }

    // Override function for query
    @Override
    public String step(String symbol) {
        String result = null;
        try {
            result = network.sendQuery(symbol);
            LogManager.logger.logQuery("Step: " + symbol + " - Result: " + result);
        } catch (Exception e) {
            LogManager.logger.logEvent("Step fail: " + symbol);
        }
        return result;
    }
    // Override function for initialization
    @Override
    public void pre() {
        try {
            network.sendLearnLibMessage("Reset");
        } catch (Exception e) {
            LogManager.logger.logEvent("Reset fail");
            throw new RuntimeException(e);
        }
    }
    // Override function for ending
    @Override
    public void post() {
    }
}
