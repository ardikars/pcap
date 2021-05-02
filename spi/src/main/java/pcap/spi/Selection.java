/*
 * Copyright (c) 2020-2021 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.spi;

import java.nio.channels.SelectionKey;
import pcap.spi.annotation.Incubating;

/**
 * Selection key.
 *
 * @since 1.3.0 (incubating)
 */
@Incubating
public interface Selection {

  /** Operation-set bit for read operations. */
  @Incubating int OPERATION_READ = SelectionKey.OP_READ;

  /** Operation-set bit for write operations. */
  @Incubating int OPERATION_WRITE = SelectionKey.OP_WRITE;

  /**
   * Get ready I/O operations.
   *
   * @return returns ready I/O operations.
   * @since 1.3.0 (incubating)
   */
  @Incubating
  int readyOperations();

  /**
   * Get the interest I/O operations for next {@link Selector#select(Timeout)}.
   *
   * @return returns interest I/O operations.
   * @since 1.3.0 (incubating)
   */
  @Incubating
  int interestOperations();

  /**
   * Set the interest I/O operations for next {@link Selector#select(Timeout)}.
   *
   * @param interestOperations operations.
   * @return returns this instance.
   * @since 1.3.0 (incubating)
   */
  @Incubating
  Selection interestOperations(int interestOperations);
}
