/*
 * Copyright (c) 2020 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.spi;

/**
 * As returned by the {@link Pcap#stats()}.
 *
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
