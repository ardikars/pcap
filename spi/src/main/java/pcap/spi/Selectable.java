/*
 * Copyright (c) 2020-2021 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.spi;

/**
 * Object that can be multiplexed via a {@link Selector}.
 *
 * @since 1.1.0
 */
public interface Selectable extends AutoCloseable {

  /**
   * {@inheritDoc}
   *
   * @throws Exception error when closing object handle (fd).
   */
  @Override
  void close() throws Exception;
}
