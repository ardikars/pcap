/*
 * Copyright (c) 2020-2021 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.spi;

import pcap.spi.annotation.Restricted;

/**
 * Object that can be multiplexed via a {@link Selector}.
 *
 * @since 1.1.0
 */
public interface Selectable extends AutoCloseable {

  /**
   * Get selectable {@code file descriptor} on Unix, or {@code HANDLE} event on Windows.
   *
   * @return returns selectable id, or {@code null} on error.
   * @throws IllegalAccessException restricted function call.
   * @since 1.3.1
   */
  @Restricted
  Object id() throws IllegalAccessException;

  /**
   * {@inheritDoc}
   *
   * @throws Exception error when closing object handle (fd).
   */
  @Override
  void close() throws Exception;

  /**
   * Register {@link Selectable} to given {@link Selector}.
   *
   * @param selector selector.
   * @param interestOperations interest operations.
   * @param attachment attachment.
   * @return returns {@link Selection} on success.
   * @throws IllegalArgumentException illegal argument.
   * @throws IllegalStateException selector is closed.
   * @since 1.3.1 (incubating)
   */
  Selection register(Selector selector, int interestOperations, Object attachment)
      throws IllegalArgumentException, IllegalStateException;
}
