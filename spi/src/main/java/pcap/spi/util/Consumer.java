/*
 * Copyright (c) 2020-2021 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.spi.util;

/**
 * Consumer.
 *
 * @param <T> the type of input.
 * @since 1.3.1 (incubating)
 */
public interface Consumer<T> {

  /**
   * Accept input.
   *
   * @param t input.
   * @since 1.3.1 (incubating)
   */
  void accept(T t);
}
