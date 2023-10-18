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
import net.automatalib.words.Word;
import net.automatalib.words.impl.GrowingMapAlphabet;
import de.learnlib.filter.cache.sul.SULCaches;

public class Learner {
    LearnConfiguration config;
    IoTSUL sul;
    NetworkManager network;
    GrowingMapAlphabet<String> alphabet;
    StatisticSUL<String, String> statisticMqSul;
    StatisticSUL<String, String> statisticEqSul;
    SUL<String, String> effectiveMqSul;
    SUL<String, String> effectiveEqSul;
    SULOracle<String, String> mqOracle;
    SULOracle<String, String> eqOracle;
    LearningAlgorithm.MealyLearner<String, String> learningAlgorithm;
    EquivalenceOracle.MealyEquivalenceOracle<String, String> equivalenceOracle;

    public Learner(LearnConfiguration config, NetworkManager network) {
        // TODO 初始化学习者
        this.config = config;
        this.network = network;

        // Build SUL and alphabet
        sul = new IoTSUL(this.config, this.network);
        alphabet = sul.getAlphabet();

        // Configure Algorithms
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

    public void learn() {
        LogManager.logger.logEvent("Start Learning");

        SimpleProfiler.start("Total time");
        boolean learning = true;
        Counter round = new Counter("Rounds", "");
        round.increment();
        LogManager.logger.logPhase("Starting round " + round.getCount());
        SimpleProfiler.start("Learning");
        learningAlgorithm.startLearning();
        SimpleProfiler.stop("Learning");

        MealyMachine<?, String, ?, String> hypothesis = learningAlgorithm.getHypothesisModel();

        while (learning) {
            // TODO 输出当前模型

            // 使用一致性检测寻找反例
            SimpleProfiler.start("Searching for counter-example");
            DefaultQuery<String, Word<String>> counterExample = equivalenceOracle.findCounterExample(hypothesis, alphabet);
            SimpleProfiler.stop("Searching for counter-example");

            if (counterExample == null) {
                learning = false;
                // TODO 输出最终模型

            } else {
                // 存在反例，进行下一轮成员查询
                LogManager.logger.logCounterexample("Current counterexample: " + counterExample);
                round.increment();
                LogManager.logger.logPhase("Starting round " + round.getCount());

                SimpleProfiler.start("Learning");
                learningAlgorithm.refineHypothesis(counterExample);
                SimpleProfiler.stop("Learning");

                hypothesis = learningAlgorithm.getHypothesisModel();
            }
        }

        SimpleProfiler.stop("Total time");

        // 输出最终结果
        LogManager.logger.logEvent("-------------------------------------------------------");
        LogManager.logger.logEvent(SimpleProfiler.getResults());
        LogManager.logger.logEvent(round.getSummary());
        LogManager.logger.logEvent(statisticMqSul.getStatisticalData().getSummary());
        LogManager.logger.logEvent(statisticEqSul.getStatisticalData().getSummary());
        LogManager.logger.logEvent("States in final hypothesis: " + hypothesis.size());
    }
}
