package org.example;

import de.learnlib.api.logging.LearnLogger;
import org.slf4j.impl.StaticLoggerBinder;

public class LogManager {
    static LearnLogger logger = LearnLogger.getLogger("Project");

    static public String resetName(String newName) {
        logger = LearnLogger.getLogger(newName);
        return newName;
    }
}
