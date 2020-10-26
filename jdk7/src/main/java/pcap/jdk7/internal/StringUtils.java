package pcap.jdk7.internal;

import java.nio.charset.StandardCharsets;
import pcap.spi.PacketBuffer;

class StringUtils {

  private StringUtils() {}

  // see netty-buffer code
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
      char ch = charSequence.charAt(i);
      if (ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n' || ch == '\0') {
        return true;
      }
    }
    return false;
  }
}
