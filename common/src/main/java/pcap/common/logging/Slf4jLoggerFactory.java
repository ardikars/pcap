/** This code is licenced under the GPL version 2. */
package pcap.common.logging;

import pcap.common.annotation.Inclubating;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
@Inclubating
class Slf4jLoggerFactory extends LoggerFactory {

  private static final LoggerFactory INSTANCE = new Slf4jLoggerFactory();

  private static final boolean HAS_SLF4J;

  private Slf4jLoggerFactory() {
    //
  }

  public static boolean hasSlf4j() {
    return HAS_SLF4J;
  }

  public static LoggerFactory getInstance() {
    return INSTANCE;
  }

  @Override
  public Logger newInstance(String name) {
    return new Slf4jLogger(org.slf4j.LoggerFactory.getLogger(name));
  }

  static {
    boolean hasSlf4j;
    try {
      Class.forName("org.slf4j.LoggerFactory");
      hasSlf4j = true;
    } catch (ClassNotFoundException e) {
      hasSlf4j = false;
    }
    HAS_SLF4J = hasSlf4j;
  }
}
