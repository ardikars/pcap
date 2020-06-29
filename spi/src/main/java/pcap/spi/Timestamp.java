/** This code is licenced under the GPL version 2. */
package pcap.spi;

/**
 * Specify a time interval (elapsed time).
 *
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 * @since 1.0.0
 */
public interface Timestamp {

  /**
   * This represents the number of whole seconds of elapsed time.
   *
   * @return returns time interval, in second.
   * @since 1.0.0
   */
  long second();

  /**
   * This is the rest of the elapsed time (a fraction of a second), represented as the number of
   * microseconds. It is always less than one million.
   *
   * @return returns time interval, in micro second.
   * @since 1.0.0
   */
  int microSecond();

  /**
   * Timestamp precision.
   *
   * @since 1.0.0
   */
  enum Precision {
    MICRO(0),
    NANO(1);

    private final int value;

    Precision(int value) {
      this.value = value;
    }

    public int value() {
      return value;
    }
  }

  /**
   * Timestamp type.
   *
   * @since 1.0.0
   */
  enum Type {
    HOST(0),
    HOST_LOWPREC(1),
    HOST_HIPREC(2),
    ADAPTER(3),
    ADAPTER_UNSYNCED(4);

    private final int value;

    Type(int value) {
      this.value = value;
    }

    public int value() {
      return value;
    }
  }
}
