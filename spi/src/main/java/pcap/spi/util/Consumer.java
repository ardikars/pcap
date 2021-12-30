/*
 * Copyright (c) 2020-2021 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.spi.util;

/**
 * Consumer.
 *
 * @param <T> the type of input.
 * @since 1.4.0
 */
public interface Consumer<T> {

  /**
   * Accept input.
   *
   * @param t input.
   * @since 1.4.0
   */
  void accept(T t);
}
