/*
 * Copyright (c) 2020 Pcap <contact@pcap.ardikars.com>
 * SPDX-License-Identifier: MIT
 */
package pcap.spi;

/**
 * As returned by the {@link Pcap#stats()}.
 *
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 * @since 1.0.0
 */
public interface Statistics {

  /**
   * Number of packets received.
   *
   * @return returns number of packets received.
   * @since 1.0.0
   */
  int received();

  /**
   * Number of packets dropped.
   *
   * @return returns number of packets dropped.
   * @since 1.0.0
   */
  int dropped();

  /**
   * Number of packets dropped by interface (only supported on some platforms).
   *
   * @return returns number of packets dropped by interface.
   * @since 1.0.0
   */
  int droppedByInterface();
}
