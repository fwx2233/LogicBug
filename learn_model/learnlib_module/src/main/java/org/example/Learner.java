package org.example;

import de.learnlib.acex.analyzers.AcexAnalyzers;
import de.learnlib.algorithms.ttt.mealy.TTTLearnerMealy;
import de.learnlib.api.SUL;
import de.learnlib.api.algorithm.LearningAlgorithm;
import de.learnlib.api.oracle.EquivalenceOracle;
import de.learnlib.api.query.DefaultQuery;
import de.learnlib.api.statistic.StatisticSUL;
import de.learnlib.filter.statistic.Counter;
import de.learnlib.filter.statistic.sul.ResetCounterSUL;
import de.learnlib.oracle.equivalence.MealyWpMethodEQOracle;
import de.learnlib.oracle.membership.SULOracle;
import de.learnlib.util.statistics.SimpleProfiler;
import net.automatalib.automata.transducers.MealyMachine;
import net.automatalib.serialization.dot.GraphDOT;
import net.automatalib.words.Word;
import net.automatalib.words.impl.GrowingMapAlphabet;
import de.learnlib.filter.cache.sul.SULCaches;

import java.io.File;
import java.io.IOException;
import java.io.PrintStream;
import java.util.*;

public class Learner {
    private static final int LEARNING_STAGE = 0;
    private static final int EQUIVALENCE_STAGE = 1;

    LearnConfiguration config;
    IoTSUL sul;
    NetworkManager network;
    CacheManager cache;
    int restartNum;
    int queryNum;
    int currentStage;
    int lastConflictNum = 0;
    // TODO 字母表的对比与筛选
    GrowingMapAlphabet<String> alphabet;
    StatisticSUL<String, String> statisticMqSul;
    StatisticSUL<String, String> statisticEqSul;
    SUL<String, String> effectiveMqSul;
    SUL<String, String> effectiveEqSul;
    SULOracle<String, String> mqOracle;
    SULOracle<String, String> eqOracle;
    LearningAlgorithm.MealyLearner<String, String> learningAlgorithm;
    EquivalenceOracle.MealyEquivalenceOracle<String, String> equivalenceOracle;

    public Learner(LearnConfiguration config, NetworkManager network, CacheManager cache) {
        // TODO 初始化学习者
        this.config = config;
        this.network = network;
        this.cache = cache;

        // 构建 SUL 和字符表
        sul = new IoTSUL(this.config, this.network,this.cache);
        alphabet = sul.getAlphabet();

        // 配置学习算法和一致性检测方法
        initAlgorithm();
    }

    private void initAlgorithm() {
        loadLearningAlgorithm();
        loadEquivalenceAlgorithm();
    }

    private void loadLearningAlgorithm() {
        // TODO 配置学习算法：构建 Oracle、选择学习算法
        // TODO 计数SUL的选择
        statisticMqSul = new ResetCounterSUL<>("membership queries", sul);
        // 使用缓存
        effectiveMqSul = SULCaches.createCache(alphabet, statisticMqSul);
        // 构建 mqOracle
        mqOracle = new SULOracle<>(effectiveMqSul);
        // 创建学习者
        learningAlgorithm = new TTTLearnerMealy<>(alphabet, mqOracle, AcexAnalyzers.LINEAR_FWD);

        LogManager.logger.logEvent("Learning algorithm (TTT) initialization complete");
    }

    private void loadEquivalenceAlgorithm() {
        // TODO 配置一致性检查方法
        // 计数
        statisticEqSul = new ResetCounterSUL<>("equivalence queries", sul);
        // 使用缓存
        effectiveEqSul = SULCaches.createCache(alphabet, statisticEqSul);
        // 构建 eqOracle
        eqOracle = new SULOracle<>(effectiveEqSul);
        // TODO 创建一致性检查方法，不同方法比较
        equivalenceOracle = new MealyWpMethodEQOracle<>(eqOracle, 2);

        LogManager.logger.logEvent("Equivalence oracle (WpMethod) initialization complete");
    }

    public static void writeDotModel(MealyMachine<?, String, ?, String> model, GrowingMapAlphabet<String> alphabet, String filename) throws IOException {
        // Write output to dot-file
        File dotFile = new File(filename);
        PrintStream psDotFile = new PrintStream(dotFile);
        GraphDOT.write(model, alphabet, psDotFile);
        psDotFile.close();
        Runtime.getRuntime().exec("dot -Tpdf -O " + filename);
    }

    public void reLearn() {
        sul.restartSUL();
        loadLearningAlgorithm();
        loadEquivalenceAlgorithm();
    }

    public void learn() throws IOException {
        boolean stop = false;
        restartNum = 0;
        while (!stop) {
            try {
                LogManager.logger.logEvent("-----------------------------------------------------------------------------------");

                LogManager.logger.logEvent("Start Learning");

                SimpleProfiler.start("Total time");
                boolean learning = true;
                Counter round = new Counter("Rounds", "");
                round.increment();
                LogManager.logger.logPhase("Starting round " + round.getCount());

                currentStage = LEARNING_STAGE;
                System.out.println("cache.index: " + cache.index);
                System.out.println("sul.currentReset: " + sul.currentReset);

                SimpleProfiler.start("Learning");
                learningAlgorithm.startLearning();
                SimpleProfiler.stop("Learning");

                System.out.println("cache.index: " + cache.index);
                System.out.println("sul.currentReset: " + sul.currentReset);

                MealyMachine<?, String, ?, String> hypothesis = learningAlgorithm.getHypothesisModel();

                while (learning) {
                    // TODO 输出当前模型
                    writeDotModel(hypothesis, alphabet, config.outputDir + "/hypothesis_" + round.getCount() + ".dot");
                    LogManager.logger.logEvent("Write model " + round.getCount());

                    // 使用一致性检测寻找反例
                    DefaultQuery<String, Word<String>> counterExample;
                    LogManager.logger.logEvent("Searching for counter-example");

                    currentStage = EQUIVALENCE_STAGE;
                    System.out.println("cache.index: " + cache.index);
                    System.out.println("sul.currentReset: " + sul.currentReset);

                    SimpleProfiler.start("Searching for counter-example");
                    counterExample = equivalenceOracle.findCounterExample(hypothesis, alphabet);
                    SimpleProfiler.stop("Searching for counter-example");

                    System.out.println("cache.index: " + cache.index);
                    System.out.println("sul.currentReset: " + sul.currentReset);

                    if (counterExample == null) {
                        learning = false;

                        // TODO 输出最终模型
                        writeDotModel(hypothesis, alphabet, config.outputDir + "/learnedModel.dot");
                    } else {
                        // If there is a counterexample, proceed to the next round of member query
                        LogManager.logger.logCounterexample("Current counterexample: " + counterExample);

                        System.out.println("cache.index: " + cache.index);
                        System.out.println("sul.currentReset: " + sul.currentReset);
                        // Check counterexamples through voting mechanisms
                        if (!sul.useCache && !checkCounterexample()){
                            // ToDo Initialize Learner to re-learn
                            LogManager.logger.logPhase("Restart for counterexample");
                            reLearn();
                            break;
                        }
                        System.out.println("cache.index: " + cache.index);
                        System.out.println("sul.currentReset: " + sul.currentReset);

                        // Counterexamples are added to the hypothesis by counterexample checking
                        round.increment();
                        LogManager.logger.logPhase("Starting round " + round.getCount());

                        currentStage = LEARNING_STAGE;

                        System.out.println("cache.index: " + cache.index);
                        System.out.println("sul.currentReset: " + sul.currentReset);
                        SimpleProfiler.start("Learning");
                        learningAlgorithm.refineHypothesis(counterExample);
                        SimpleProfiler.stop("Learning");

                        System.out.println("cache.index: " + cache.index);
                        System.out.println("sul.currentReset: " + sul.currentReset);
                        hypothesis = learningAlgorithm.getHypothesisModel();


                        System.out.println("cache.index: " + cache.index);
                        System.out.println("sul.currentReset: " + sul.currentReset);
                    }
                }

                if (!learning) {

                    SimpleProfiler.stop("Total time");

                    // 输出最终结果
                    LogManager.logger.logEvent("-------------------------------------------------------");
                    LogManager.logger.logEvent(SimpleProfiler.getResults());
                    LogManager.logger.logEvent(round.getSummary());
                    LogManager.logger.logEvent(statisticMqSul.getStatisticalData().getSummary());
                    LogManager.logger.logEvent(statisticEqSul.getStatisticalData().getSummary());
                    LogManager.logger.logEvent("States in final hypothesis: " + hypothesis.size());

                    // Stop Learning
                    stop = true;
                    network.closeConnection();
                }
            } catch (IllegalArgumentException e) {
                if (!checkConflict()) {
                    stop = true;
                    LogManager.logger.logPhase("The same nondeterministic query is generated too many times");
                    network.closeConnection();
                }
            } catch (IllegalMonitorStateException e) {
                LogManager.logger.logPhase("Restart for IllegalMonitorStateException");
            }
        }
    }

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

    private List<String> processVotes(List<String> vote_0, List<List<String>> votes) {
        int n = vote_0.size();
        List<String> result = new ArrayList<>();

        for (int i = 0; i < n; i++) {
            String vote0 = vote_0.get(i);
            String vote1 = votes.get(0).get(i);
            String vote2 = votes.get(1).get(i);
            String vote3 = votes.get(2).get(i);

            String winner = getWinner(vote0, vote1, vote2, vote3);
            result.add(winner);
        }

        return result;
    }

    public  boolean compareLists(List<String> list1, List<String> list2) {
        // 检查是否为null
        if (list1 == null || list2 == null) {
            return false;
        }

        // 检查长度是否相等
        if (list1.size() != list2.size()) {
            return false;
        }

        // 检查每个位置上的元素是否相同
        for (int i = 0; i < list1.size(); i++) {
            if (!Objects.equals(list1.get(i), list2.get(i))) {
                return false;
            }
        }

        // 如果通过所有检查，则两个列表相等
        return true;
    }


    private boolean checkCounterexample() throws IOException {
        LogManager.logger.logPhase("Check counterexample");

        System.out.println("cache.index: " + cache.index);
        System.out.println("sul.currentReset: " + sul.currentReset);

        List<String> symbol, result, finalResult;
        List<List<String>> results = new ArrayList<>();
        symbol = new ArrayList<>(cache.getSymbol());
        result = new ArrayList<>(cache.getResult());
        System.out.println("symbol: " + symbol);
        System.out.println("results: " + results);
        cache.reloadCache();
        System.out.println("queryNum: " + queryNum);
        System.out.println("resetNum: " + cache.resetNum);
        for (int i = 0; i < 3; i++) {
            List<String> tmp = network.checkCounterExample(symbol);
            results.add(tmp);
            System.out.println("results: " + results);
        }
        System.out.println("results: " + results);
        finalResult = processVotes(result, results);
        System.out.println("result: " + result);
        System.out.println("finalResult: " + finalResult);

        System.out.println("cache.index: " + cache.index);
        System.out.println("sul.currentReset: " + sul.currentReset);
        if (compareLists(result, finalResult)) {
            cache.reloadCache(symbol, finalResult);
            return true;
        } else {
            cache.reloadCache();
            cache.index = 1;
            return false;
        }
    }

    private boolean checkConflict() throws IOException {
        List<String> symbol, result, finalResult;
        List<List<String>> results = new ArrayList<>();
        symbol = new ArrayList<>(cache.getSymbol());
        result = new ArrayList<>(cache.getResult());
        System.out.println("symbol: " + symbol);
        System.out.println("results: " + results);
        cache.reloadCache();
        System.out.println("queryNum: " + queryNum);
        System.out.println("resetNum: " + cache.resetNum);

//        results.add(cache.getResult());
//        System.out.println("symbol: " + symbol);
//        System.out.println("result: " + results.get(0));
        if (currentStage == LEARNING_STAGE){
            LogManager.logger.logPhase("Check conflict query during learning");
            if (lastConflictNum == cache.index) {
                restartNum++;
            } else
                restartNum = 0;
            if (restartNum > 3) {
                return false;
            }
            System.out.println("queryNum: " + queryNum);
            System.out.println("resetNum: " + cache.resetNum);
            System.out.println("lastConflictNum: " + lastConflictNum);
            System.out.println("cache.index: " + cache.index);
            for (int i = 0; i < 3; i++) {
                List<String> tmp = network.checkCounterExample(symbol);
                results.add(tmp);
                System.out.println("results: " + results);
            }
            System.out.println("results: " + results);
            finalResult = processVotes(result, results);
            System.out.println("result: " + result);
            System.out.println("finalResult: " + finalResult);
            cache.reloadCache(symbol, finalResult);
            System.out.println("queryNum: " + queryNum);
            System.out.println("resetNum: " + cache.resetNum);
        } else if (currentStage == EQUIVALENCE_STAGE) {
            LogManager.logger.logPhase("Check conflict query during equivalence");
            System.out.println("queryNum: " + queryNum);
            System.out.println("resetNum: " + cache.resetNum);
            if (lastConflictNum == cache.index) {
                restartNum++;
            } else
                restartNum = 0;
            if (restartNum > 3) {
                return false;
            }
            System.out.println("restartNum: " + restartNum);
        }
        LogManager.logger.logPhase("Restart for conflict query");
        reLearn();
        cache.index = 1;
        return true;
    }
}
