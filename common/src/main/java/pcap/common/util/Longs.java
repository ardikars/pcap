/*
 * Copyright (c) 2020-2022 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.common.util;

/**
 * Longs utils.
 *
 * @since 1.0.0
 */
public final class Longs {

  private Longs() {
    //
  }

  /**
   * Byte array to long.
   *
   * @param values byte array.
   * @return long representation.
   * @since 1.0.0
   */
  public static long toLong(byte[] values) {
    Validate.notInBounds(values.length, 0, 8);
    return (((values[0] & 0xFFL) << 56)
        | ((values[1] & 0xFFL) << 48)
        | ((values[2] & 0xFFL) << 40)
        | ((values[3] & 0xFFL) << 32)
        | ((values[4] & 0xFFL) << 24)
        | ((values[5] & 0xFFL) << 16)
        | ((values[6] & 0xFFL) << 8)
        | (values[7] & 0xFFL));
  }

  /**
   * Byte array to long (little endian).
   *
   * @param values byte array.
   * @return long representation.
   * @since 1.0.0
   */
  public static long toLongLE(byte[] values) {
    Validate.notInBounds(values.length, 0, 8);
    return (values[0] & 0xFFL)
        | ((values[1] & 0xFFL) << 8)
        | ((values[2] & 0xFFL) << 16)
        | ((values[3] & 0xFFL) << 24)
        | ((values[4] & 0xFFL) << 32)
        | ((values[5] & 0xFFL) << 40)
        | ((values[6] & 0xFFL) << 48)
        | ((values[7] & 0xFFL) << 56);
  }

  /**
   * Byte array to long.
   *
   * @param values byte array.
   * @param offset offset.
   * @return long representation.
   * @since 1.0.0
   */
  public static long toLong(byte[] values, int offset) {
    Validate.notInBounds(values.length, offset, 8);
    return (((values[offset] & 0xFFL) << 56)
        | ((values[offset + 1] & 0xFFL) << 48)
        | ((values[offset + 2] & 0xFFL) << 40)
        | ((values[offset + 3] & 0xFFL) << 32)
        | ((values[offset + 4] & 0xFFL) << 24)
        | ((values[offset + 5] & 0xFFL) << 16)
        | ((values[offset + 6] & 0xFFL) << 8)
        | (values[offset + 7] & 0xFFL));
  }

  /**
   * Byte array to long (little endian).
   *
   * @param values byte array.
   * @param offset offset.
   * @return long representation.
   * @since 1.0.0
   */
  public static long toLongLE(byte[] values, int offset) {
    Validate.notInBounds(values.length, offset, 8);
    return (values[offset] & 0xFFL)
        | ((values[offset + 1] & 0xFFL) << 8)
        | ((values[offset + 2] & 0xFFL) << 16)
        | ((values[offset + 3] & 0xFFL) << 24)
        | ((values[offset + 4] & 0xFFL) << 32)
        | ((values[offset + 5] & 0xFFL) << 40)
        | ((values[offset + 6] & 0xFFL) << 48)
        | ((values[offset + 7] & 0xFFL) << 56);
  }
}
