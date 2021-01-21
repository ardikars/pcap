/*
 * Copyright (c) 2020-2021 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.spi;

/**
 * Item in a list of interfaces.
 *
 * @since 1.0.0
 */
public interface Interface extends Iterable<Interface> {

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
   * @return returns interface flags.
   * @since 1.0.0
   */
  int flags();
}
