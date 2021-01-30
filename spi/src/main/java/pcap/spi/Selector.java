/*
 * Copyright (c) 2020-2021 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.spi;

import pcap.spi.exception.TimeoutException;

/**
 * A multiplexor of {@link Selectable} objects.
 *
 * @since 1.1.0
 */
public interface Selector extends AutoCloseable {

  /**
   * Selects a set of registered objects whose corresponding {@link Selectable} are ready for I/O
   * operations.
   *
   * <p>This method performs a blocking selection operation. It returns only after at least one
   * {@link Selectable} is selected or timeout reached.
   *
   * @param timeout timeout.
   * @return returns {@link Selectable} objects whose ready to perform I/O operations.
   * @throws TimeoutException If an I/O timeout occurs.
   * @since 1.1.0
   */
  Iterable<Selectable> select(Timeout timeout) throws TimeoutException;

  /**
   * Register given {@link Selectable} object to this {@link Selector}.
   *
   * @param selectable selectable object.
   * @return returns this {@link Selector}.
   * @since 1.1.0
   */
  Selector register(Selectable selectable);
}
