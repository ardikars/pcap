/** This code is licenced under the GPL version 2. */
package pcap.common.logging;

import pcap.common.annotation.Inclubating;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
@Inclubating
class NoLoggerFactory extends LoggerFactory {

  private static final LoggerFactory INSTANCE = new NoLoggerFactory();

  public static LoggerFactory getInstance() {
    return INSTANCE;
  }

  @Override
  Logger newInstance(String name) {
    return new NoLogger(name);
  }
}
