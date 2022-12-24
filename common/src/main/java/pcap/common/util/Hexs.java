/*
 * Copyright (c) 2020-2022 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.common.util;

import java.util.Arrays;

/**
 * Hex utils.
 *
 * @since 1.0.0
 */
public final class Hexs {

  static final byte[] HEX2B;
  static final char[] HEXDUMP_TABLE;
  static final String HEXDUMP_PRETTY_HEADER =
      ""
          + "         +-------------------------------------------------+\n"
          + "         |  0  1  2  3  4  5  6  7  8  9  a  b  c  d  e  f |\n"
          + "+--------+-------------------------------------------------+--------+\n";
  static final String HEXDUMP_PRETTY_FOOTER =
      "+--------+-------------------------------------------------+--------+";

  static {
    HEXDUMP_TABLE = new char[256 * 4];
    final char[] digits = "0123456789abcdef".toCharArray();
    for (int i = 0; i < 256; i++) {
      HEXDUMP_TABLE[i << 1] = digits[i >>> 4 & 0x0F];
      HEXDUMP_TABLE[(i << 1) + 1] = digits[i & 0x0F];
    }
    HEX2B = new byte[Character.MAX_VALUE + 1];
    Arrays.fill(HEX2B, (byte) -1);
    HEX2B['0'] = (byte) 0;
    HEX2B['1'] = (byte) 1;
    HEX2B['2'] = (byte) 2;
    HEX2B['3'] = (byte) 3;
    HEX2B['4'] = (byte) 4;
    HEX2B['5'] = (byte) 5;
    HEX2B['6'] = (byte) 6;
    HEX2B['7'] = (byte) 7;
    HEX2B['8'] = (byte) 8;
    HEX2B['9'] = (byte) 9;
    HEX2B['A'] = (byte) 10;
    HEX2B['B'] = (byte) 11;
    HEX2B['C'] = (byte) 12;
    HEX2B['D'] = (byte) 13;
    HEX2B['E'] = (byte) 14;
    HEX2B['F'] = (byte) 15;
    HEX2B['a'] = (byte) 10;
    HEX2B['b'] = (byte) 11;
    HEX2B['c'] = (byte) 12;
    HEX2B['d'] = (byte) 13;
    HEX2B['e'] = (byte) 14;
    HEX2B['f'] = (byte) 15;
  }

  private Hexs() {
    //
  }

  /**
   * Helper to decode half of a hexadecimal number from a string.
   *
   * @param c The ASCII character of the hexadecimal number to decode. Must be in the range {@code
   *     [0-9a-fA-F]}.
   * @return The hexadecimal value represented in the ASCII character given, or {@code -1} if the
   *     character is invalid.
   */
  public static int decodeHexNibble(final char c) {
    // Character.digit() is not used here, as it addresses a larger
    // set of characters (both ASCII and full-width latin letters).
    return HEX2B[c];
  }

  /**
   * Parse hex strings to byte array.
   *
   * @param hexStream hex strings.
   * @return returns byte array representation.
   * @since 1.0.0
   */
  public static byte[] parseHex(String hexStream) {
    Validate.nullPointer(hexStream);
    // see
    // https://github.com/netty/netty/blob/4.1/common/src/main/java/io/netty/util/internal/StringUtil.java
    int length = hexStream.length();
    if ((length & 1) != 0) {
      throw new IllegalArgumentException(String.format("Invalid length: %d", length));
    }
    if (length == 0) {
      return pcap.common.util.Arrays.EMPTY_BYTES;
    }
    int fromIndex = 0;
    if (hexStream.charAt(0) == '0' && hexStream.charAt(1) == 'x') {
      fromIndex += 2;
      length -= 2;
    }
    final byte[] bytes = new byte[length >>> 1];
    for (int i = 0; i < length; i += 2) {
      int hi = HEX2B[hexStream.charAt(fromIndex + i)];
      int lo = HEX2B[hexStream.charAt(fromIndex + i + 1)];
      if (hi == -1 || lo == -1) {
        throw new IllegalArgumentException(
            String.format(
                "Invalid hex byte '%s' at index %d of '%s'",
                hexStream.subSequence(fromIndex + i, fromIndex + i + 2), fromIndex + i, hexStream));
      }
      bytes[i >>> 1] = (byte) ((hi << 4) + lo);
    }
    return bytes;
  }
}
