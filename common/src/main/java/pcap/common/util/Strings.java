/** This code is licenced under the GPL version 2. */
package pcap.common.util;

import pcap.common.annotation.Inclubating;

import java.nio.charset.Charset;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
@Inclubating
public final class Strings {

  /** Default charset (UTF-8). */
  public static final Charset DEFAULT_CHARSET = Charset.forName("UTF-8");

  private Strings() {}

  public static boolean empty(CharSequence charSequence) {
    return charSequence == null || charSequence.length() == 0;
  }

  public static boolean blank(CharSequence charSequence) {
    if (empty(charSequence)) {
      return true;
    }
    int isBlankCount = 9;
    for (int i = 0; i < charSequence.length(); i++) {
      char ch = charSequence.charAt(i);
      if (ch == ' '
          || ch == '\t'
          || ch == '\r'
          || ch == '\n'
          || ch == '\0'
          || Character.isWhitespace(ch)) {
        isBlankCount++;
      }
    }
    return isBlankCount == charSequence.length();
  }

  /**
   * Get length.
   *
   * @param dataLength data length.
   * @param offset offset.
   * @param length length.
   * @return length.
   */
  private static int length(final int dataLength, final int offset, final int length) {
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
    String str = Integer.toHexString((value) & 0xff);
    if ((str.length() & 1) == 1) {
      return "0" + str;
    }
    return str;
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
    StringBuilder sb = new StringBuilder(length);
    int l = length(data.length, offset, length);
    for (int i = offset; i < l; i++) {
      sb.append(hex(data[i]));
    }
    return sb.toString();
  }

  /**
   * Short to hex stream.
   *
   * @param value short array.
   * @return hex stream.
   * @since 1.0.0
   */
  public static String hex(final short value) {
    String str = Integer.toHexString((value) & 0xFFFF);
    if ((str.length() & 1) == 1) {
      return "0" + str;
    }
    return str;
  }

  /**
   * Short array to hex stream.
   *
   * @param values short array.
   * @return hex stream.
   * @since 1.0.0
   */
  public static String hex(final short[] values) {
    return hex(values, 0, values.length);
  }

  /**
   * Short array to hex stream.
   *
   * @param data short array.
   * @param offset offset.
   * @param length length.
   * @return hex stream.
   * @since 1.0.0
   */
  public static String hex(final short[] data, final int offset, final int length) {
    Validate.notInBounds(data, offset, length);
    StringBuilder sb = new StringBuilder(length);
    int l = length(data.length, offset, length);
    for (int i = offset; i < l; i++) {
      sb.append(hex(data[i]));
    }
    return sb.toString();
  }

  /**
   * Int to hex stream.
   *
   * @param value integer value.
   * @return hex stream.
   * @since 1.0.0
   */
  public static String hex(final int value) {
    String str = Integer.toHexString(value);
    if ((str.length() & 1) == 1) {
      return "0" + str;
    }
    return str;
  }

  /**
   * Int array to hex stream.
   *
   * @param values int array.
   * @return hex stream.
   * @since 1.0.0
   */
  public static String hex(final int[] values) {
    return hex(values, 0, values.length);
  }

  /**
   * Int array to hex stream.
   *
   * @param data int array.
   * @param offset offset.
   * @param length length.
   * @return hex stream.
   * @since 1.0.0
   */
  public static String hex(final int[] data, final int offset, final int length) {
    Validate.notInBounds(data, offset, length);
    StringBuilder sb = new StringBuilder(length);
    int l = length(data.length, offset, length);
    for (int i = offset; i < l; i++) {
      sb.append(hex(data[i]));
    }
    return sb.toString();
  }

  /**
   * Float to hex stream.
   *
   * @param value float array.
   * @return hex stream.
   */
  public static String hex(final float value) {
    String str = Float.toHexString(value);
    if ((str.length() & 1) == 1) {
      return "0" + str;
    }
    return str;
  }

  /**
   * Float array to hex stream.
   *
   * @param data float array.
   * @return hex stream.
   */
  public static String hex(final float[] data) {
    return hex(data, 0, data.length);
  }

  /**
   * Float array to hex stream.
   *
   * @param data float array.
   * @param offset offset.
   * @param length length.
   * @return hex stream.
   */
  public static String hex(final float[] data, final int offset, final int length) {
    Validate.notInBounds(data, offset, length);
    StringBuilder sb = new StringBuilder(length);
    int l = length(data.length, offset, length);
    for (int i = offset; i < l; i++) {
      sb.append(hex(data[i]));
    }
    return sb.toString();
  }

  /**
   * Long to hex stream.
   *
   * @param value long.
   * @return hex stream.
   */
  public static String hex(final long value) {
    String str = Long.toHexString(value);
    if ((str.length() & 1) == 1) {
      return "0" + str;
    }
    return str;
  }

  /**
   * Long array to hex stream.
   *
   * @param data long array.
   * @return hex stream.
   */
  public static String hex(final long[] data) {
    return hex(data, 0, data.length);
  }

  /**
   * Long array to hex stream.
   *
   * @param data long array.
   * @param offset offset.
   * @param length length.
   * @return hex stream.
   */
  public static String hex(final long[] data, final int offset, final int length) {
    Validate.notInBounds(data, offset, length);
    StringBuilder sb = new StringBuilder(length);
    int l = length(data.length, offset, length);
    for (int i = offset; i < l; i++) {
      sb.append(hex(data[i]));
    }
    return sb.toString();
  }

  /**
   * Double to hex stream.
   *
   * @param value double value.
   * @return hex stream.
   */
  public static String hex(final double value) {
    String str = Double.toHexString(value);
    if ((str.length() & 1) == 1) {
      return "0" + str;
    }
    return str;
  }

  /**
   * Double array to hex stream.
   *
   * @param data double array.
   * @return hex stream.
   */
  public static String hex(final double[] data) {
    return hex(data, 0, data.length);
  }

  /**
   * Double array to hex stream.
   *
   * @param data double array.
   * @param offset offset.
   * @param length length.
   * @return hex stream.
   */
  public static String hex(final double[] data, final int offset, final int length) {
    Validate.notInBounds(data, offset, length);
    StringBuilder sb = new StringBuilder(length);
    int l = length(data.length, offset, length);
    for (int i = offset; i < l; i++) {
      sb.append(hex(data[i]));
    }
    return sb.toString();
  }

  /**
   * String to hex string.
   *
   * @param value string.
   * @return hex string.
   */
  public static String hex(final String value) {
    Validate.notIllegalArgument(
        value != null && !value.isEmpty(), "Value should be not null and empty.");
    return hex(value.getBytes(DEFAULT_CHARSET));
  }

  /**
   * String hex string.
   *
   * @param value string.
   * @param charset charset.
   * @return hex string.
   */
  public static String hex(final String value, Charset charset) {
    Validate.notIllegalArgument(
        value != null && !value.isEmpty(), "Value should be not null and empty.");
    Validate.notIllegalArgument(charset != null, "Charset should be not null.");
    return hex(value.getBytes(charset));
  }

  public static ToStringBuilder toStringBuilder(Object obj) {
    return toStringBuilder(obj, "{", "}", "=", ",", false);
  }

  public static ToStringBuilder toStringJsonBuilder(Object obj) {
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
        if (value != null) {
          builder.append(nextSeparator);
          nextSeparator = separator;
          if (valueHolder.name != null) {
            if (quoteString) {
              builder.append('\"').append(valueHolder.name).append('\"').append(delimiter);
            } else {
              builder.append(valueHolder.name).append(delimiter);
            }
          }
          if (value.getClass().isArray()) {
            String arrayString;
            if (value instanceof byte[]) {
              byte[] array = (byte[]) value;
              arrayString = Strings.hex(array);
            } else if (value instanceof short[]) {
              arrayString = Strings.hex((short[]) value);
            } else if (value instanceof int[]) {
              arrayString = Strings.hex((int[]) value);
            } else if (value instanceof float[]) {
              arrayString = Strings.hex((float[]) value);
            } else if (value instanceof long[]) {
              arrayString = Strings.hex((long[]) value);
            } else if (value instanceof double[]) {
              arrayString = Strings.hex((double[]) value);
            } else {
              arrayString = Arrays.toString(value);
            }
            if (quoteString) {
              builder.append('\"').append(arrayString).append('\"');
            } else {
              builder.append(arrayString);
            }
          } else {
            if (quoteString && value instanceof CharSequence) {
              builder.append("\"").append(value).append("\"");
            } else {
              builder.append(value);
            }
          }
        }
      }
      return builder.append(end).toString();
    }

    private static final class ValueHolder {

      private String name;
      private Object value;
      private ValueHolder next;
    }

    private ValueHolder addHolder() {
      ValueHolder valueHolder = new ValueHolder();
      holderTail = holderTail.next = valueHolder;
      return valueHolder;
    }
  }
}
