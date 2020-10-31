/** This code is licenced under the GPL version 2. */
package pcap.common.util;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
public final class Strings {

  private Strings() {
    //
  }

  /**
   * Ensure given string is not empty.
   *
   * @param charSequence string.
   * @return returns {@code true} if empty, @{@code false} otherwise.
   */
  public static boolean empty(CharSequence charSequence) {
    return charSequence == null || charSequence.length() == 0;
  }

  /**
   * @param charSequence string.
   * @param fallback fallback.
   * @return returns string.
   */
  public static CharSequence empty(CharSequence charSequence, CharSequence fallback) {
    return empty(charSequence) ? fallback : charSequence;
  }

  /**
   * Ensure given string isn't blank.
   *
   * @param charSequence string.
   * @return returns {@code true} if blank, {@code false} otherwise.
   */
  public static boolean blank(CharSequence charSequence) {
    if (empty(charSequence)) {
      return true;
    }
    int length = charSequence.length();
    for (int i = 0; i < length; i++) {
      char ch = charSequence.charAt(i);
      if (ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n' || ch == '\0') {
        return true;
      }
    }
    return false;
  }

  /**
   * @param charSequence string.
   * @param fallback fallback.
   * @return returns string.
   */
  public static CharSequence blank(CharSequence charSequence, CharSequence fallback) {
    return blank(charSequence) ? fallback : charSequence;
  }

  /**
   * Get length.
   *
   * @param dataLength data length.
   * @param offset offset.
   * @param length length.
   * @return length.
   */
  static int length(final int dataLength, final int offset, final int length) {
    int l;
    if (dataLength != length && offset != 0) {
      l = offset + length;
    } else {
      l = length;
    }
    return l;
  }

  /**
   * Byte to hex value.
   *
   * @param value value.
   * @return hex format.
   * @since 1.0.0
   */
  public static String hex(final byte value) {
    char[] buf = new char[2];
    System.arraycopy(Hexs.HEXDUMP_TABLE, (value & 0xFF) << 1, buf, 0, 2);
    return new String(buf);
  }

  /**
   * Byte array to hex stream.
   *
   * @param data byte array.
   * @return hex stream.
   * @since 1.0.0
   */
  public static String hex(final byte[] data) {
    return hex(data, 0, data.length);
  }

  /**
   * Byte array to hex stream.
   *
   * @param data byte array.
   * @param offset offset.
   * @param length length.
   * @return hex stream.
   * @since 1.0.0
   */
  public static String hex(final byte[] data, final int offset, final int length) {
    Validate.notInBounds(data, offset, length);
    if (length == 0) {
      return "";
    }
    int endIndex = offset + length;
    char[] buf = new char[length << 1];

    int srcIdx = offset;
    int dstIdx = 0;
    for (; srcIdx < endIndex; srcIdx++, dstIdx += 2) {
      System.arraycopy(Hexs.HEXDUMP_TABLE, (data[srcIdx] & 0xFF) << 1, buf, dstIdx, 2);
    }
    return new String(buf);
  }

  /**
   * Byte to pretty hex value.
   *
   * @param value value.
   * @return pretty hex dump.
   * @since 1.0.0
   */
  public static String prettyHex(final byte value) {
    return prettyHex(new byte[] {value});
  }

  /**
   * Byte array to pretty hex stream.
   *
   * @param data byte array.
   * @return pretty hex dump.
   * @since 1.0.0
   */
  public static String prettyHex(final byte[] data) {
    return prettyHex(data, 0, data.length);
  }

  /**
   * Byte array to pretty hex dump.
   *
   * @param data byte array.
   * @param offset offset.
   * @param length length.
   * @return pretty hex dump.
   * @since 1.0.0
   */
  public static String prettyHex(final byte[] data, final int offset, final int length) {
    Validate.notInBounds(data, offset, length);
    StringBuilder result = new StringBuilder();
    StringBuilder builder = new StringBuilder();
    int pos = offset;
    int max = length;
    int lineNumber = 0;
    builder.append(Hexs.HEXDUMP_PRETTY_HEADER);
    while (pos < max) {
      builder.append(String.format("%08d", lineNumber++) + " | ");
      int lineMax = Math.min(max - pos, 16);
      for (int i = 0; i < lineMax; i++) {
        int index = (data[pos + i] & 0xFF) << 1;
        builder.append(
            new String(new char[] {Hexs.HEXDUMP_TABLE[index], Hexs.HEXDUMP_TABLE[++index]}));
        builder.append(" ");
      }
      builder.append("| ");
      for (int i = 0; i < lineMax; i++) {
        char c = (char) data[pos + i];
        if (c < 32 || c > 127) {
          c = '.';
        }
        builder.append(c);
      }
      builder.append("\n");
      result.append(builder);
      builder.setLength(0);
      pos += 16;
    }
    result.append(Hexs.HEXDUMP_PRETTY_FOOTER);
    return result.toString();
  }

  public static ToStringBuilder toStringBuilder(Object obj) {
    return toStringBuilder(obj, "{", "}", "=", ",", false);
  }

  public static ToStringBuilder toStringJsonBuilder() {
    return toStringBuilder("", "{", "}", ":", ",", true);
  }

  public static ToStringBuilder toStringBuilder(
      Object obj,
      String start,
      String end,
      String delimiter,
      String separator,
      boolean quoteString) {
    return toStringBuilder(
        obj.getClass().getSimpleName(), start, end, delimiter, separator, quoteString);
  }

  public static ToStringBuilder toStringBuilder(
      String name,
      String start,
      String end,
      String delimiter,
      String separator,
      boolean quoteString) {
    return new ToStringBuilder(name, start, end, delimiter, separator, quoteString);
  }

  public static final class ToStringBuilder {

    private final String name;
    private final String start;
    private final String end;
    private final String delimiter;
    private final String separator;
    private final boolean quoteString;
    private final ValueHolder holderHead = new ValueHolder();
    private ValueHolder holderTail = holderHead;

    private ToStringBuilder(
        String name,
        String start,
        String end,
        String delimiter,
        String separator,
        boolean quoteString) {
      this.name = name;
      this.start = start;
      this.end = end;
      this.delimiter = delimiter;
      this.separator = separator;
      this.quoteString = quoteString;
    }

    public ToStringBuilder add(String name, Object value) {
      Validate.notIllegalArgument(name != null && !name.isEmpty());
      ValueHolder valueHolder = addHolder();
      valueHolder.name = name;
      valueHolder.value = value;
      return this;
    }

    @Override
    public String toString() {
      String nextSeparator = "";
      StringBuilder builder = new StringBuilder(32).append(name).append(start);
      for (ValueHolder valueHolder = holderHead.next;
          valueHolder != null;
          valueHolder = valueHolder.next) {
        Object value = valueHolder.value;
        value = Validate.nullPointerThenReturns(value, "null");
        builder.append(nextSeparator);
        nextSeparator = separator;
        if (quoteString) {
          builder.append('\"').append(valueHolder.name).append('\"').append(delimiter);
        } else {
          builder.append(valueHolder.name).append(delimiter);
        }
        if (value.getClass().isArray()) {
          appendArrayValue(builder, value);
        } else {
          appendStringValue(builder, value);
        }
      }
      return builder.append(end).toString();
    }

    private void appendStringValue(StringBuilder builder, Object value) {
      if (quoteString && value instanceof CharSequence) {
        builder.append("\"").append(value).append("\"");
      } else {
        builder.append(value);
      }
    }

    private void appendArrayValue(StringBuilder builder, Object value) {
      String arrayString = value.toString();
      if (quoteString) {
        builder.append('\"').append(arrayString).append('\"');
      } else {
        builder.append(arrayString);
      }
    }

    private ValueHolder addHolder() {
      ValueHolder valueHolder = new ValueHolder();
      holderTail = holderTail.next = valueHolder;
      return valueHolder;
    }

    private static final class ValueHolder {

      private String name;
      private Object value;
      private ValueHolder next;
    }
  }
}
