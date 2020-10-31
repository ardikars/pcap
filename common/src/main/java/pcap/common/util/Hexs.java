package pcap.common.util;

import java.util.regex.Pattern;

public final class Hexs {

  static final char[] HEXDUMP_TABLE;

  static final String HEXDUMP_PRETTY_HEADER =
      ""
          + "         +-------------------------------------------------+\n"
          + "         |  0  1  2  3  4  5  6  7  8  9  a  b  c  d  e  f |\n"
          + "+--------+-------------------------------------------------+--------+\n";

  static final String HEXDUMP_PRETTY_FOOTER =
      "+--------+---------------------------------" + "----------------+--------+";

  private static final Pattern NO_SEPARATOR_HEX_STRING_PATTERN =
      Pattern.compile("\\A([0-9a-fA-F][0-9a-fA-F])+\\z");

  static {
    HEXDUMP_TABLE = new char[256 * 4];
    final char[] digits = "0123456789abcdef".toCharArray();
    for (int i = 0; i < 256; i++) {
      HEXDUMP_TABLE[i << 1] = digits[i >>> 4 & 0x0F];
      HEXDUMP_TABLE[(i << 1) + 1] = digits[i & 0x0F];
    }
  }

  private Hexs() {
    //
  }

  public static byte[] parseHex(String hexStream) {
    Validate.nullPointer(hexStream);
    if (hexStream.startsWith("0x")) {
      hexStream = hexStream.substring(2);
    }
    hexStream = hexStream.replaceAll("\\s+", "").trim();
    if (!NO_SEPARATOR_HEX_STRING_PATTERN.matcher(hexStream).matches()) {
      throw new IllegalArgumentException();
    }
    int len = hexStream.length();
    byte[] data = new byte[len >> 1];
    for (int i = 0; i < len; i += 2) {
      data[i / 2] =
          (byte)
              ((Character.digit(hexStream.charAt(i), 16) << 4)
                  + Character.digit(hexStream.charAt(i + 1), 16));
    }
    return data;
  }
}
