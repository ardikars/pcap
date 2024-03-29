/*
 * Copyright (c) 2020-2023 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.spi;

/**
 * Generic per-packet information.
 *
 * <p>{@link PacketHeader} supply the appropriate version of {@link Timestamp}, regardless of
 * whether your system supports 32-bit {@link Timestamp}, 64-bit {@link Timestamp}, or both.
 *
 * <p>Note: On-disk format of {@code savefiles} uses 32-bit {@link Timestamp}.
 *
 * @since 1.0.0
 */
public interface PacketHeader {

  /**
   * Timestamp per-packet.
   *
   * @return returns timestamp.
   * @since 1.0.0
   */
  Timestamp timestamp();

  /**
   * Length of portion present (must be less then or equal to {@link PacketHeader#length()}).
   *
   * @return returns length of portion present.
   * @since 1.0.0
   */
  int captureLength();

  /**
   * Length this packet (off wire).
   *
   * @return returns length this packet (off wire).
   * @since 1.0.0
   */
  int length();
}
