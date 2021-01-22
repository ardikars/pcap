/*
 * Copyright (c) 2020-2021 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.spi;

import pcap.spi.annotation.Incubating;

/**
 * Timeout.
 *
 * @since 1.1.0
 */
@Incubating
public interface Timeout {

  /**
   * Get second.
   *
   * @return returns second.
   * @since 1.1.0
   */
  @Incubating
  long second();

  /**
   * Get microsecond.
   *
   * @return returns microsecond.
   * @since 1.1.0
   */
  @Incubating
  long microSecond();

  /**
   * Timeout precision.
   *
   * @since 1.1.0
   */
  @Incubating
  enum Precision {
    /**
     * Use timeout with microsecond precision.
     *
     * @since 1.1.0
     */
    @Incubating
    MICRO(0),
    /**
     * Use timeout with nanosecond precision.
     *
     * @since 1.1.0
     */
    @Incubating
    NANO(1);

    private final int value;

    Precision(int value) {
      this.value = value;
    }

    /**
     * Get precision ID.
     *
     * @return returns precision ID.
     */
    @Incubating
    public int value() {
      return value;
    }
  }
}
