/**
 * This code is licenced under the GPL version 2.
 */
package pcap.common.logging;

import org.apache.logging.log4j.LogManager;

/**
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 */
class Log4j2LoggerFactory extends LoggerFactory {

    private static final LoggerFactory INSTANCE = new Log4j2LoggerFactory();

    private static final boolean HAS_LOG4J2;

    private Log4j2LoggerFactory() {
        //
    }

    public static boolean hasLog4j2() {
        return HAS_LOG4J2;
    }

    public static LoggerFactory getInstance() {
        return INSTANCE;
    }

    @Override
    public Logger newInstance(String name) {
        return new Log4j2Logger(LogManager.getLogger(name));
    }

    static {
        boolean hasLog4j2;
        try {
            Class.forName("org.apache.logging.log4j.LogManager");
            hasLog4j2 = true;
        } catch (ClassNotFoundException e) {
            hasLog4j2 = false;
        }
        HAS_LOG4J2 = hasLog4j2;
    }

}
