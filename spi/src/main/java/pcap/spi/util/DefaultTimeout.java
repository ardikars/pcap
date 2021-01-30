/*
 * Copyright (c) 2020-2021 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.spi.util;

import pcap.spi.Timeout;

/**
 * Default timeout.
 *
 * @since 1.1.0
 */
public class DefaultTimeout implements Timeout {

  private final long second;
  private final long microSecond;

  /**
   * Create timeout instance.
   *
   * @param timeout timeout.
   * @param precision precision.
   * @since 1.1.0
   */
  public DefaultTimeout(long timeout, Timeout.Precision precision) {
    if (precision != null) {
      if (precision == Precision.MICRO) {
        this.second = timeout / 1000000L;
        this.microSecond = timeout;
      } else {
        this.second = timeout / 1000000000L;
        this.microSecond = timeout / 1000L;
      }
    } else {
      this.second = 0L;
      this.microSecond = 0L;
    }
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
    final StringBuilder sb = new StringBuilder("DefaultTimeout{");
    sb.append("second=").append(second);
    sb.append(", microSecond=").append(microSecond);
    sb.append('}');
    return sb.toString();
  }
}
