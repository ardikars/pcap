/*
 * Copyright (c) 2020-2023 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.spi;

/**
 * Timeout.
 *
 * @since 1.1.0
 */
public interface Timeout {

  /**
   * Get second.
   *
   * @return returns second.
   * @since 1.1.0
   */
  long second();

  /**
   * Get microsecond.
   *
   * @return returns microsecond.
   * @since 1.1.0
   */
  long microSecond();

  /**
   * Timeout precision.
   *
   * @since 1.1.0
   */
  enum Precision {
    /**
     * Use timeout with microsecond precision.
     *
     * @since 1.1.0
     */
    MICRO(0),
    /**
     * Use timeout with nanosecond precision.
     *
     * @since 1.1.0
     */
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
    public int value() {
      return value;
    }
  }
}
