/*
 * Copyright (c) 2020-2023 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.spi;

/**
 * A handle for writing packet to a {@code savefile}.
 *
 * @since 1.0.0
 */
public interface Dumper extends AutoCloseable {

  /**
   * Write a packet to a {@code savefile}.
   *
   * @param header packet header wrapper ({@link PacketHeader}).
   * @param buffer packet buffer wrapper ({@link PacketBuffer}).
   * @since 1.0.0
   */
  void dump(PacketHeader header, PacketBuffer buffer);

  /**
   * {@code savefile} position.
   *
   * @return returns {@code savefile} position.
   * @since 1.0.0
   */
  long position();

  /**
   * Flushes the output buffer to the {@code savefile}.
   *
   * @since 1.0.0
   */
  void flush();

  /**
   * Closes a {@code savefile}.
   *
   * @since 1.0.0
   */
  @Override
  void close();
}
