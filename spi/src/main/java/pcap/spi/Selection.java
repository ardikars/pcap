/*
 * Copyright (c) 2020-2021 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.spi;

import java.nio.channels.SelectionKey;
import pcap.spi.exception.NoSuchSelectableException;

/**
 * Selection key.
 *
 * @since 1.4.0
 */
public interface Selection {

  /**
   * Operation-set bit for read operations.
   *
   * @since 1.4.0
   */
  int OPERATION_READ = SelectionKey.OP_READ;

  /**
   * Operation-set bit for write operations.
   *
   * @since 1.4.0
   */
  int OPERATION_WRITE = SelectionKey.OP_WRITE;

  /**
   * Attach some object.
   *
   * @param attachment attachment.
   * @return returns this instance.
   * @since 1.4.0
   */
  Selection attach(Object attachment);

  /**
   * Get attachment.
   *
   * @return returns attachment or {@code null} if no attached object.
   * @since 1.4.0
   */
  Object attachment();

  /**
   * Get ready I/O operations.
   *
   * @return returns ready I/O operations.
   * @since 1.4.0
   */
  int readyOperations();

  /**
   * Is readable.
   *
   * @return returns {@code true} if {@link Selectable} is readable, {@code false} otherwise.
   * @since 1.4.0
   */
  boolean isReadable();

  /**
   * Is writable.
   *
   * @return returns {@code true} if {@link Selectable} is writable, {@code false} otherwise.
   * @since 1.4.0
   */
  boolean isWritable();

  /**
   * Get the interest I/O operations for next {@link Selector#select(Timeout)}.
   *
   * @return returns interest I/O operations.
   * @since 1.4.0
   */
  int interestOperations();

  /**
   * Set the interest I/O operations for next {@link Selector#select(Timeout)}.
   *
   * @param interestOperations operations.
   * @return returns this instance.
   * @throws IllegalStateException selectable object is canceled.
   * @since 1.4.0
   */
  Selection interestOperations(int interestOperations) throws IllegalStateException;

  /**
   * Get selector for this {@link Selection}.
   *
   * @return returns {@link Selector}.
   * @since 1.4.0
   */
  Selector selector();

  /**
   * Get {@link Selection} object for this {@link Selection}.
   *
   * @return returns {@link Selectable}.
   * @since 1.4.0
   */
  Selectable selectable();

  /**
   * De-register {@link Selectable} from {@link Selection#selector()}.
   *
   * @throws IllegalStateException selector is closed or selectable object is already canceled.
   * @since 1.4.0
   */
  void cancel() throws IllegalStateException, NoSuchSelectableException;
}
