/*
 * Copyright (c) 2020 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.spi;

/**
 * Specify a time interval (elapsed time).
 *
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
  long microSecond();

  /**
   * Time stamp resolution types.
   *
   * <p>Not all systems and interfaces will necessarily support all of these resolutions when doing
   * live captures; all of them can be requested when reading a {@code savefile}.
   *
   * @since 1.0.0
   */
  enum Precision {

    /**
     * Use timestamps with microsecond precision (default).
     *
     * @since 1.0.0
     */
    MICRO(0),
    /**
     * Use timestamps with nanosecond precision.
     *
     * @since 1.0.0
     */
    NANO(1);

    private final int value;

    Precision(int value) {
      this.value = value;
    }

    /**
     * Value will be pass to native code.
     *
     * @return returns native timestamp precision value.
     * @since 1.0.0
     */
    public int value() {
      return value;
    }
  }

  /**
   * Timestamp type.
   *
   * <p>Not all systems and interfaces will necessarily support all of these.
   *
   * <p>Note that time stamps synchronized with the system clock can go backwards, as the system
   * clock can go backwards. If a clock is not in sync with the system clock, that could be because
   * the system clock isn't keeping accurate time, because the other clock isn't keeping accurate
   * time, or both.
   *
   * <p>Note that host-provided time stamps generally correspond to the time when the time-stamping
   * code sees the packet; this could be some unknown amount of time after the first or last bit of
   * the packet is received by the network adapter, due to batching of interrupts for packet
   * arrival, queueing delays, etc.
   *
   * @since 1.0.0
   */
  enum Type {
    /**
     * Offering time stamps provided by the host machine, rather than by the capture device, but not
     * committing to any characteristics of the time stamp.
     *
     * @since 1.0.0
     */
    HOST(0),
    /**
     * Provided by the host machine, that's low-precision but relatively cheap to fetch; it's
     * normally done using the system clock, so it's normally synchronized with times you'd fetch
     * from system calls.
     *
     * @since 1.0.0
     */
    HOST_LOWPREC(1),
    /**
     * Provided by the host machine, that's high-precision; it might be more expensive to fetch. It
     * is synchronized with the system clock.
     */
    HOST_HIPREC(2),
    /**
     * High-precision time stamp supplied by the capture device; it's synchronized with the system
     * clock.
     *
     * @since 1.0.0
     */
    ADAPTER(3),
    /**
     * High-precision time stamp supplied by the capture device; it's not synchronized with the
     * system clock.
     *
     * @since 1.0.0
     */
    ADAPTER_UNSYNCED(4),
    /**
     * Provided by the host machine, that's high-precision; it might be more expensive to fetch. It
     * is not synchronized with the system clock, and might have problems with time stamps for
     * packets received on different CPUs, depending on the platform. It might be more likely to be
     * strictly monotonic than HOST_HIPREC.
     *
     * @since 1.0.0
     */
    HOST_HIPREC_UNSYNCED(5);

    private final int value;

    Type(int value) {
      this.value = value;
    }

    /**
     * Value will be pass to native code.
     *
     * @return returns native timestamp type value.
     * @since 1.0.0
     */
    public int value() {
      return value;
    }
  }
}
