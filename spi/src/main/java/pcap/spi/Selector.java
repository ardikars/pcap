/*
 * Copyright (c) 2020-2021 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.spi;

import pcap.spi.exception.NoSuchSelectableException;
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
   * @param timeout a {@link Timeout}.
   * @return returns {@link Selectable} objects whose ready to perform I/O operations.
   * @throws TimeoutException If an I/O timeout occurs.
   * @throws NoSuchSelectableException no {@link Selectable} registered on this {@link Selector}.
   * @throws IllegalStateException this {@link Selectable} might be closed.
   * @throws IllegalArgumentException {@link Timeout} is not sufficient.
   * @since 1.1.0
   */
  Iterable<Selectable> select(Timeout timeout)
      throws TimeoutException, NoSuchSelectableException, IllegalStateException,
          IllegalArgumentException;

  /**
   * Register given {@link Selectable} object to this {@link Selector}.
   *
   * @param selectable {@link Selectable} object.
   * @return returns this {@link Selector}.
   * @throws IllegalStateException this {@link Selectable} might be closed.
   * @throws IllegalArgumentException given {@link Selectable} is null, not supported, or already
   *     registered on this {@link Selector}.
   * @since 1.1.0
   */
  Selector register(Selectable selectable) throws IllegalArgumentException, IllegalStateException;
}
