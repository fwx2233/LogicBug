package org.example;

import de.learnlib.api.SUL;
import net.automatalib.words.impl.GrowingMapAlphabet;

import java.io.IOException;
import java.util.Objects;

public class IoTSUL implements SUL<String, String> {
    GrowingMapAlphabet<String> alphabet;
    NetworkManager network;
    CacheManager cache;
    boolean useCache, isReset, isNull = false;
    int currentReset;
    public IoTSUL(LearnConfiguration config, NetworkManager network, CacheManager cache) {
        // TODO 初始化 SUL
        alphabet = new GrowingMapAlphabet<>(config.aM.words);
        this.network = network;
        this.cache = cache;
        currentReset = 0;
        this.useCache = config.useCache;
    }

    public GrowingMapAlphabet<String> getAlphabet() {
        return alphabet;
    }

    public void restartSUL() {
        currentReset = 0;
        useCache = true;
    }

    // Rewrite the SUL interface function to push the system down
    @Override
    public String step(String symbol) {
        String result = null;
        try {
            // To process character functions, you need to use the Socket interaction module
            LogManager.logger.logEvent("[STEP] " + symbol);
            isReset = false;
            if (useCache) {
                result = cache.get(symbol);
                LogManager.logger.logQuery("[CACHE] Step: " + symbol + " - Result: " + result);
            }else {
                result = network.sendQuery(NetworkManager.QUERY_MESSAGE, symbol);
//                LogManager.logger.logEvent(String.valueOf(result.length()));
                if (result.isEmpty()){
                    isNull = true;
                    LogManager.logger.logEvent("[WARNING] Receive null");
                    throw new RestartException(result);
                }

                if (Objects.equals(result, "RestartLearning")) {
                    LogManager.logger.logEvent("[WARNING] " + result);
                    throw new RestartException(result);
                }
                LogManager.logger.logEvent("[TEST] " + result);
                cache.add(symbol, result);
                LogManager.logger.logQuery("[QUERY] Step: " + symbol + " - Result: " + result);
            }
        } catch (IOException e) {
            LogManager.logger.logEvent("[WRONG] Step fail: " + symbol);
        }
        return result;
    }
    // Rewrite the SUL interface function to initialize the target system
    @Override
    public void pre() {
        String result = null;
        try {
            // TODO 重置 Reset 函数
            LogManager.logger.logEvent("[RESET]");
            isReset = true;
            currentReset++;
            if (!useCache || currentReset > cache.getResetNum()) {
                useCache = false;
                result = network.sendQuery(NetworkManager.LEARNLIB_MESSAGE, "Reset");
                if (result.isEmpty()){
                    isNull = true;
                    LogManager.logger.logEvent("[WARNING] Receive null");
                    throw new RestartException(result);
                }

                if (Objects.equals(result, "RestartLearning")) {
                    LogManager.logger.logEvent("[WARNING] " + result);
                    throw new RestartException(result);
                }
                cache.writeCache(false);
            } else {
                LogManager.logger.logEvent("[CACHE] Reset");
            }
        } catch (IOException e) {
            LogManager.logger.logEvent("[WRONG] Reset fail");
            throw new RuntimeException(e);
        }
    }
    // 重写SUL接口函数，结束目标系统
    @Override
    public void post() {
    }
}
