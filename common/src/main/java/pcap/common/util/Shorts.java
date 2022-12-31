/*
 * Copyright (c) 2020-2023 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.common.util;

/**
 * Shorts utils.
 *
 * @since 1.0.0
 */
public final class Shorts {

  private Shorts() {
    //
  }

  /**
   * Byte array to short.
   *
   * @param values byte array.
   * @return short representation.
   * @since 1.0.0
   */
  public static short toShort(byte[] values) {
    Validate.notInBounds(values.length, 0, 2);
    return (short) ((values[0] & 0xFF) << 8 | values[1] & 0xFF);
  }

  /**
   * Byte array to short.
   *
   * @param values byte array.
   * @param offset offset.
   * @return short representation.
   * @since 1.0.0
   */
  public static short toShort(byte[] values, int offset) {
    Validate.notInBounds(values.length, offset, 2);
    return (short) ((values[offset] & 0xFF) << 8 | values[offset + 1] & 0xFF);
  }

  /**
   * Byte array to short (little endian).
   *
   * @param values byte array.
   * @return short representation.
   * @since 1.0.0
   */
  public static short toShortLE(byte[] values) {
    Validate.notInBounds(values.length, 0, 2);
    return (short) (values[0] & 0xFF | (values[1] & 0xFF) << 8);
  }

  /**
   * Byte array to short (little endian).
   *
   * @param values byte array.
   * @param offset offset.
   * @return short representation.
   * @since 1.0.0
   */
  public static short toShortLE(byte[] values, int offset) {
    Validate.notInBounds(values.length, offset, 2);
    return (short) (values[offset] & 0xFF | (values[offset + 1] & 0xFF) << 8);
  }
}
