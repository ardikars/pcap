/*
 * Copyright (c) 2020 Pcap <contact@pcap.ardikars.com>
 * SPDX-License-Identifier: MIT
 */
package pcap.spi;

/**
 * A handle for writing packet to a {@code savefile}.
 *
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
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
