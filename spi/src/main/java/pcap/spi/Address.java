/*
 * Copyright (c) 2020-2021 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.spi;

import java.net.InetAddress;

/**
 * Representation of an interface address.
 *
 * @since 1.0.0
 */
public interface Address extends Iterable<Address> {

  /**
   * Next available address.
   *
   * @return returns next address if available, {@code null} otherwise.
   * @since 1.0.0
   */
  Address next();

  /**
   * Interface address.
   *
   * @return returns interface address.
   * @since 1.0.0
   */
  InetAddress address();

  /**
   * Netmask for interface address ({@link #address()}).
   *
   * @return returns netmask for ({@link #address()}).
   * @since 1.0.0
   */
  InetAddress netmask();

  /**
   * Brodcast address for interface address ({@link #address()}).
   *
   * @return returns brodcast address for ({@link #address()}).
   * @since 1.0.0
   */
  InetAddress broadcast();

  /**
   * P2P destination address for interface address ({@link #address()}).
   *
   * @return returns P2P destination address for ({@link #address()}).
   * @since 1.0.0
   */
  InetAddress destination();
}
