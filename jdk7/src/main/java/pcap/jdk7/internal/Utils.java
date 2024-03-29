/*
 * Copyright (c) 2020-2023 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.jdk7.internal;

import java.nio.charset.StandardCharsets;
import pcap.spi.PacketBuffer;
import pcap.spi.exception.ErrorException;

class Utils {

  static final int MAJOR;
  static final int MINOR;
  static final int PATCH;

  static {
    String version = NativeMappings.pcap_lib_version();
    char[] chars = version.toCharArray();
    int startIndex = 0;
    int endIndex = 0;
    for (int i = chars.length - 1; i >= 0; i--) {
      if (chars[i] == '-') {
        endIndex = i;
      }
      if (Character.isDigit(chars[i])) {
        startIndex = i;
        if (i - 1 >= 0 && chars[i - 1] == ' ') {
          break;
        }
      }
    }
    String[] splited =
        version.substring(startIndex, endIndex < startIndex ? chars.length : endIndex).split("\\.");
    if (splited.length > 1) {
      MAJOR = Integer.parseInt(splited[0]);
    } else {
      MAJOR = 1;
    }
    if (splited.length > 2) {
      MINOR = Integer.parseInt(splited[1]);
    } else {
      MINOR = 0;
    }
    if (splited.length > 3) {
      PATCH = Integer.parseInt(splited[2]);
    } else {
      PATCH = 0;
    }
  }

  private Utils() {}

  // this method copied from netty-buffer code.
  // see at:
  // https://github.com/netty/netty/blob/4.1/buffer/src/main/java/io/netty/buffer/ByteBufUtil.java
  static long setCharSequence(
      PacketBuffer self, long index, CharSequence seq, PacketBuffer.Charset charset) {
    long writtenBytes;
    final byte WRITE_UTF_UNKNOWN = (byte) '?';
    final char MAX_CHAR_VALUE = 255;
    if (charset.name().equals(StandardCharsets.UTF_8.name())) {
      int len = seq.length();

      long oldIndex = index;

      for (int i = 0; i < len; i++) {
        char c = seq.charAt(i);
        if (c < 0x80) {
          self.setByte(index++, (byte) c);
        } else if (c < 0x800) {
          self.setByte(index++, (byte) (0xc0 | (c >> 6)));
          self.setByte(index++, (byte) (0x80 | (c & 0x3f)));
        } else if (c >= '\uD800' && c <= '\uDFFF') {
          if (!Character.isHighSurrogate(c)) {
            self.setByte(index++, WRITE_UTF_UNKNOWN);
            continue;
          }
          final char c2;
          try {
            c2 = seq.charAt(++i);
          } catch (IndexOutOfBoundsException ignored) {
            self.setByte(index++, WRITE_UTF_UNKNOWN);
            break;
          }
          if (!Character.isLowSurrogate(c2)) {
            self.setByte(index++, WRITE_UTF_UNKNOWN);
            self.setByte(index++, Character.isHighSurrogate(c2) ? WRITE_UTF_UNKNOWN : c2);
          } else {
            int codePoint = Character.toCodePoint(c, c2);
            self.setByte(index++, (byte) (0xf0 | (codePoint >> 18)));
            self.setByte(index++, (byte) (0x80 | ((codePoint >> 12) & 0x3f)));
            self.setByte(index++, (byte) (0x80 | ((codePoint >> 6) & 0x3f)));
            self.setByte(index++, (byte) (0x80 | (codePoint & 0x3f)));
          }
        } else {
          self.setByte(index++, (byte) (0xe0 | (c >> 12)));
          self.setByte(index++, (byte) (0x80 | ((c >> 6) & 0x3f)));
          self.setByte(index++, (byte) (0x80 | (c & 0x3f)));
        }
      }
      writtenBytes = index - oldIndex;
    } else if (charset.name().equals(StandardCharsets.US_ASCII.name())) {
      for (int i = 0; i < seq.length(); i++) {
        self.setByte(index++, (byte) (seq.charAt(i) > MAX_CHAR_VALUE ? '?' : seq.charAt(i)));
      }
      writtenBytes = seq.length();
    } else {
      byte[] chars = seq.toString().getBytes(java.nio.charset.Charset.forName(charset.name()));
      self.setBytes(index, chars);
      writtenBytes = chars.length;
    }
    return writtenBytes;
  }

  static boolean empty(CharSequence charSequence) {
    return charSequence == null || charSequence.length() == 0;
  }

  static boolean blank(CharSequence charSequence) {
    if (empty(charSequence)) {
      return true;
    }
    int length = charSequence.length();
    for (int i = 0; i < length; i++) {
      char character = charSequence.charAt(i);
      if (!Character.isWhitespace(character) && character != '\0') {
        return false;
      }
    }
    return true;
  }

  static void requireNonBlank(CharSequence charSequence, String message) {
    if (blank(charSequence)) {
      throw new IllegalArgumentException(message);
    }
  }

  static void requireNonNull(Object obj, String message) {
    if (obj == null) {
      throw new IllegalArgumentException(message);
    }
  }

  static void validateVersion(int major, int minor, int patch) throws ErrorException {
    if (!isSupported(major, major, patch)) {
      throw new ErrorException(
          String.format(
              "version: %d.%d.%d (expected: minimal version(%d.%d.%d))",
              MAJOR, MINOR, PATCH, major, minor, patch));
    }
  }

  static boolean isSupported(int major, int minor, int patch) {
    return Utils.MAJOR > major
        || (Utils.MAJOR == major && Utils.MINOR > minor)
        || (Utils.MAJOR == major && Utils.MINOR == minor && Utils.PATCH >= patch);
  }
}
