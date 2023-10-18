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

    // 重写SUL接口函数，推动系统向下运行
    @Override
    public String step(String symbol) {
        String result = null;
        try {
            // TODO 处理字符函数，需要使用 Socket 交互模块
            result = network.sendQuery(symbol);
            LogManager.logger.logQuery("Step: " + symbol + " - Result: " + result);
        } catch (Exception e) {
            LogManager.logger.logEvent("Step fail: " + symbol);
        }
        return result;
    }
    // 重写SUL接口函数，初始化目标系统
    @Override
    public void pre() {
        try {
            // TODO 重置 Reset 函数
            network.sendQuery("Reset");
        } catch (Exception e) {
            LogManager.logger.logEvent("Reset fail");
            throw new RuntimeException(e);
        }
    }
    // 重写SUL接口函数，结束目标系统
    @Override
    public void post() {
    }
}
