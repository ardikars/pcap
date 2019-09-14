/** This code is licenced under the GPL version 2. */
package pcap.common.logging;

import pcap.common.annotation.Inclubating;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
@Inclubating
public interface Logger {

  String name();

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
