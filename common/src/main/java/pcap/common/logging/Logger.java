/** This code is licenced under the GPL version 2. */
package pcap.common.logging;

import pcap.common.annotation.Inclubating;

/**
 * Logger api specification.
 *
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 * @since 1.0.0
 */
@Inclubating
public interface Logger {

  /**
   * Logger holder name.
   *
   * @return returns logger name.
   * @since 1.0.0
   */
  String name();

  /**
   * Check the given level is enabled or not.
   *
   * @param level logging level.
   * @return returns {@code true} if given level is enabled, {@code otherwise}.
   */
  boolean isEnabled(LogLevel level);

  boolean isDebugEnabled();

  boolean isInfoEnabled();

  boolean isWarnEnabled();

  boolean isErrorEnabled();

  void log(LogLevel level, String message);

  void log(LogLevel level, String format, Object arg1);

  void log(LogLevel level, String format, Object arg1, Object arg2);

  void log(LogLevel level, String format, Object... args);

  void log(LogLevel level, Throwable throwable);

  void log(LogLevel level, String message, Throwable throwable);

  void debug(String message);

  void debug(Throwable throwable);

  void debug(String format, Object arg1);

  void debug(String format, Object arg1, Object arg2);

  void debug(String format, Object... args);

  void debug(String message, Throwable throwable);

  void info(String message);

  void info(Throwable throwable);

  void info(String format, Object obj1);

  void info(String format, Object obj1, Object obj2);

  void info(String format, Object... args);

  void info(String message, Throwable throwable);

  void warn(String message);

  void warn(Throwable throwable);

  void warn(String format, Object arg1);

  void warn(String format, Object arg1, Object obj2);

  void warn(String format, Object... args);

  void warn(String message, Throwable throwable);

  void error(String message);

  void error(Throwable throwable);

  void error(String format, Object obj1);

  void error(String format, Object obj1, Object obj2);

  void error(String format, Object... args);

  void error(String message, Throwable throwable);
}
