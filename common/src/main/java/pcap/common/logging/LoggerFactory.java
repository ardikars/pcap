/** This code is licenced under the GPL version 2. */
package pcap.common.logging;

import pcap.common.annotation.Inclubating;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
@Inclubating
public abstract class LoggerFactory {

  static LoggerFactory DEFAULT_LOGGER_FACTORY;

  private static LoggerFactory getDefaultLoggerFactory() {
    if (DEFAULT_LOGGER_FACTORY == null) {
      DEFAULT_LOGGER_FACTORY = newDefaultFactory();
    }
    return DEFAULT_LOGGER_FACTORY;
  }

  public static Logger getLogger(String name) {
    return getDefaultLoggerFactory().newInstance(name);
  }

  public static Logger getLogger(Class<?> clazz) {
    return getLogger(clazz.getName());
  }

  public static Logger getLogger(Object object) {
    return getLogger(object.getClass());
  }

  private static LoggerFactory newDefaultFactory() {
    LoggerFactory loggerFactory;
    if (Slf4jLoggerFactory.hasSlf4j()) {
      loggerFactory = Slf4jLoggerFactory.getInstance();
    } else if (Log4j2LoggerFactory.hasLog4j2()) {
      loggerFactory = Log4j2LoggerFactory.getInstance();
    } else {
      loggerFactory = NoLoggerFactory.getInstance();
    }
    return loggerFactory;
  }

  static boolean hasClass(String name) {
    try {
      Class.forName(name);
      return true;
    } catch (ClassNotFoundException e) {
      return false;
    }
  }

  abstract Logger newInstance(String name);
}
