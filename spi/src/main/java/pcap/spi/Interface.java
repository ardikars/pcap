/*
 * Copyright (c) 2020-2021 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.spi;

import pcap.spi.annotation.Incubating;

/**
 * Item in a list of interfaces.
 *
 * @since 1.0.0
 */
public interface Interface extends Iterable<Interface> {

  /**
   * Interface is loopback.
   *
   * @since 1.3.1 (incubating)
   */
  @Incubating int PCAP_IF_LOOPBACK = 0x00000001;

  /**
   * Interface is up.
   *
   * @since 1.3.1 (incubating)
   */
  @Incubating int PCAP_IF_UP = 0x00000002;

  /**
   * Interface is running.
   *
   * @since 1.3.1 (incubating)
   */
  @Incubating int PCAP_IF_RUNNING = 0x00000004;

  /**
   * Interface is wireless (*NOT* necessarily Wi-Fi!).
   *
   * @since 1.3.1 (incubating)
   */
  @Incubating int PCAP_IF_WIRELESS = 0x00000008;

  /**
   * Connection status.
   *
   * @since 1.3.1 (incubating)
   */
  @Incubating int PCAP_IF_CONNECTION_STATUS = 0x00000030;
  /**
   * Unknown.
   *
   * @since 1.3.1 (incubating)
   */
  @Incubating int PCAP_IF_CONNECTION_STATUS_UNKNOWN = 0x00000000;

  /**
   * Connected.
   *
   * @since 1.3.1 (incubating)
   */
  @Incubating int PCAP_IF_CONNECTION_STATUS_CONNECTED = 0x00000010;

  /**
   * Disconnected.
   *
   * @since 1.3.1 (incubating)
   */
  @Incubating int PCAP_IF_CONNECTION_STATUS_DISCONNECTED = 0x00000020;

  /**
   * Not applicable.
   *
   * @since 1.3.1 (incubating)
   */
  @Incubating int PCAP_IF_CONNECTION_STATUS_NOT_APPLICABLE = 0x00000030;

  /**
   * Next available interface.
   *
   * @return returns next interface if available, {@code null} otherwise.
   * @since 1.0.0
   */
  Interface next();

  /**
   * Interface name.
   *
   * @return returns interface name.
   * @since 1.0.0
   */
  String name();

  /**
   * Textual description of interface, or {@code null}.
   *
   * @return returns interface description.
   * @since 1.0.0
   */
  String description();

  /**
   * Interface addresses.
   *
   * @return returns interface addresses.
   * @since 1.0.0
   */
  Address addresses();

  /**
   * Interface flags.
   *
   * <pre>{@code
   * Interface source = ..;
   * if (source.flags() & Interface.UP != 0) {
   *     // interface is up
   * }
   * if (source.flags() & Interface.RUNNING != 0) {
   *     // Interface is running
   * }
   * }</pre>
   *
   * @return returns interface flags.
   * @since 1.0.0
   */
  int flags();
}
