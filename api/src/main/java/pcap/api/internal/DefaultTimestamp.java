/** This code is licenced under the GPL version 2. */
package pcap.api.internal;

import pcap.common.util.Strings;
import pcap.spi.Timestamp;

/**
 * Default timestamp.
 *
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 */
public class DefaultTimestamp implements Timestamp {

  volatile long second;
  volatile int microSecond;

  public DefaultTimestamp(long second, int microSecond) {
    this.second = second;
    this.microSecond = microSecond;
  }

  @Override
  public long second() {
    return second;
  }

  @Override
  public long microSecond() {
    return microSecond;
  }

  @Override
  public String toString() {
    return Strings.toStringBuilder(this)
        .add("second", second)
        .add("microSecond", microSecond)
        .toString();
  }
}
