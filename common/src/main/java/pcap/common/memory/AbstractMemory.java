/** This code is licenced under the GPL version 2. */
package pcap.common.memory;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import pcap.common.annotation.Inclubating;
import pcap.common.util.Strings;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
@Inclubating
public abstract class AbstractMemory<B> implements Memory {

  protected B buffer;

  protected long capacity;
  protected long maxCapacity;

  protected long writtenBytes = 0L;
  protected boolean freed;
  private long readerIndex;
  private long writerIndex;
  private long markedReaderIndex;
  private long markedWriterIndex;

  protected AbstractMemory(
      B buffer, long capacity, long maxCapacity, long readerIndex, long writerIndex) {
    this.capacity = capacity;
    this.maxCapacity = maxCapacity;
    this.readerIndex = readerIndex;
    this.writerIndex = writerIndex;
    this.buffer = buffer;
  }

  @Override
  public long capacity() {
    return capacity;
  }

  @Override
  public long maxCapacity() {
    return maxCapacity;
  }

  @Override
  public long readerIndex() {
    return readerIndex;
  }

  @Override
  public Memory readerIndex(long readerIndex) {
    if (readerIndex < 0 || readerIndex > writerIndex) {
      throw new IndexOutOfBoundsException(
          String.format(
              "readerIndex: %d (expected: 0 <= readerIndex <= writerIndex(%d))",
              readerIndex, writerIndex));
    }
    this.readerIndex = readerIndex;
    return this;
  }

  @Override
  public long writerIndex() {
    return writerIndex;
  }

  @Override
  public Memory writerIndex(long writerIndex) {
    if (writerIndex < readerIndex || writerIndex > capacity()) {
      throw new IndexOutOfBoundsException(
          String.format(
              "writerIndex: %d (expected: readerIndex(%d) <= writerIndex <= capacity(%d))",
              writerIndex, readerIndex, capacity()));
    }
    this.writerIndex = writerIndex;
    return this;
  }

  @Override
  public Memory setIndex(long readerIndex, long writerIndex) {
    if (readerIndex < 0 || readerIndex > writerIndex || writerIndex > capacity()) {
      throw new IndexOutOfBoundsException(
          String.format(
              "readerIndex: %d, writerIndex: %d (expected: 0 <= readerIndex <= writerIndex <= capacity(%d))",
              readerIndex, writerIndex, capacity()));
    }
    this.readerIndex = readerIndex;
    this.writerIndex = writerIndex;
    return this;
  }

  @Override
  public long readableBytes() {
    return writerIndex - readerIndex;
  }

  @Override
  public long writableBytes() {
    return capacity() - writerIndex;
  }

  @Override
  public long maxWritableBytes() {
    return maxCapacity() - writerIndex;
  }

  @Override
  public boolean isReadable() {
    return writerIndex > readerIndex;
  }

  @Override
  public boolean isReadable(long numBytes) {
    return writerIndex - readerIndex >= numBytes;
  }

  @Override
  public boolean isWritable() {
    return capacity() > writerIndex;
  }

  @Override
  public boolean isWritable(long numBytes) {
    return capacity() - writerIndex >= numBytes;
  }

  @Override
  public Memory clear() {
    readerIndex = writerIndex = 0;
    return this;
  }

  @Override
  public Memory markReaderIndex() {
    markedReaderIndex = readerIndex;
    return this;
  }

  @Override
  public Memory resetReaderIndex() {
    readerIndex(markedReaderIndex);
    return this;
  }

  @Override
  public Memory markWriterIndex() {
    markedWriterIndex = writerIndex;
    return this;
  }

  @Override
  public Memory resetWriterIndex() {
    writerIndex(markedWriterIndex);
    return this;
  }

  @Override
  public Memory ensureWritable(long minWritableBytes) {
    if (minWritableBytes < 0) {
      throw new IllegalArgumentException(
          String.format("minWritableBytes: %d (expected: >= 0)", minWritableBytes));
    }
    checkWritableBytes(minWritableBytes);
    return this;
  }

  @Override
  public boolean getBoolean(long index) {
    return getByte(index) != 0;
  }

  @Override
  public short getUnsignedByte(long index) {
    return (short) (getByte(index) & 0xFF);
  }

  @Override
  public int getUnsignedShort(long index) {
    return getShort(index) & 0xFFFF;
  }

  @Override
  public int getUnsignedShortLE(long index) {
    return getShortLE(index) & 0xFFFF;
  }

  @Override
  public long getUnsignedInt(long index) {
    return getInt(index) & 0xFFFFFFFFL;
  }

  @Override
  public long getUnsignedIntLE(long index) {
    return getIntLE(index) & 0xFFFFFFFFL;
  }

  @Override
  public float getFloat(long index) {
    return Float.intBitsToFloat(getInt(index));
  }

  @Override
  public float getFloatLE(long index) {
    return Float.intBitsToFloat(this.getIntLE(index));
  }

  @Override
  public double getDouble(long index) {
    return Double.longBitsToDouble(getLong(index));
  }

  @Override
  public double getDoubleLE(long index) {
    return Double.longBitsToDouble(this.getLongLE(index));
  }

  @Override
  public Memory getBytes(long index, Memory dst) {
    getBytes(index, dst, dst.writableBytes());
    return this;
  }

  @Override
  public Memory getBytes(long index, Memory dst, long length) {
    getBytes(index, dst, dst.writerIndex(), length);
    dst.writerIndex(dst.writerIndex() + length);
    return this;
  }

  @Override
  public Memory getBytes(long index, byte[] dst) {
    getBytes(index, dst, 0, dst.length);
    return this;
  }

  @Override
  public CharSequence getCharSequence(long index, long length, Charset charset) {
    byte[] bytes = new byte[(int) length & 0x7FFFFFFF];
    this.getBytes(index, bytes);
    return new String(bytes, charset);
  }

  @Override
  public Memory setBoolean(long index, boolean value) {
    setByte(index, value ? 1 : 0);
    return this;
  }

  @Override
  public Memory setFloat(long index, float value) {
    setInt(index, Float.floatToRawIntBits(value));
    return this;
  }

  @Override
  public Memory setFloatLE(long index, float value) {
    return this.setIntLE(index, Float.floatToRawIntBits(value));
  }

  @Override
  public Memory setDouble(long index, double value) {
    setLong(index, Double.doubleToRawLongBits(value));
    return this;
  }

  @Override
  public Memory setDoubleLE(long index, double value) {
    return this.setLongLE(index, Double.doubleToRawLongBits(value));
  }

  @Override
  public Memory setBytes(long index, Memory src) {
    setBytes(index, src, src.readableBytes());
    return this;
  }

  @Override
  public Memory setBytes(long index, Memory src, long length) {
    checkIndex(index, length);
    if (src == null) {
      throw new NullPointerException("src");
    }
    if (length > src.readableBytes()) {
      throw new IndexOutOfBoundsException(
          String.format(
              "length(%d) exceeds src.readableBytes(%d) where src is: %s",
              length, src.readableBytes(), src));
    }

    setBytes(index, src, src.readerIndex(), length);
    src.readerIndex(src.readerIndex() + length);
    return this;
  }

  @Override
  public Memory setBytes(long index, byte[] src) {
    setBytes(index, src, 0, src.length);
    return this;
  }

  @Override
  public Memory setCharSequence(long index, CharSequence seq, Charset charset) {
    // see netty-buffer code
    final byte WRITE_UTF_UNKNOWN = (byte) '?';
    final char MAX_CHAR_VALUE = 255;
    if (charset.equals(StandardCharsets.UTF_8)) {
      int len = seq.length();

      long oldIndex = index;

      for (int i = 0; i < len; i++) {
        char c = seq.charAt(i);
        if (c < 0x80) {
          this.setByte(index++, (byte) c);
        } else if (c < 0x800) {
          this.setByte(index++, (byte) (0xc0 | (c >> 6)));
          this.setByte(index++, (byte) (0x80 | (c & 0x3f)));
        } else if (c >= '\uD800' && c <= '\uDFFF') {
          if (!Character.isHighSurrogate(c)) {
            this.setByte(index++, WRITE_UTF_UNKNOWN);
            continue;
          }
          final char c2;
          try {
            c2 = seq.charAt(++i);
          } catch (IndexOutOfBoundsException ignored) {
            this.setByte(index++, WRITE_UTF_UNKNOWN);
            break;
          }
          if (!Character.isLowSurrogate(c2)) {
            this.setByte(index++, WRITE_UTF_UNKNOWN);
            this.setByte(index++, Character.isHighSurrogate(c2) ? WRITE_UTF_UNKNOWN : c2);
          } else {
            int codePoint = Character.toCodePoint(c, c2);
            this.setByte(index++, (byte) (0xf0 | (codePoint >> 18)));
            this.setByte(index++, (byte) (0x80 | ((codePoint >> 12) & 0x3f)));
            this.setByte(index++, (byte) (0x80 | ((codePoint >> 6) & 0x3f)));
            this.setByte(index++, (byte) (0x80 | (codePoint & 0x3f)));
          }
        } else {
          this.setByte(index++, (byte) (0xe0 | (c >> 12)));
          this.setByte(index++, (byte) (0x80 | ((c >> 6) & 0x3f)));
          this.setByte(index++, (byte) (0x80 | (c & 0x3f)));
        }
      }
      writtenBytes = index - oldIndex;
    } else if (charset.equals(StandardCharsets.US_ASCII)) {
      for (int i = 0; i < seq.length(); i++) {
        this.setByte(index++, (byte) (seq.charAt(i) > MAX_CHAR_VALUE ? '?' : seq.charAt(i)));
      }
      writtenBytes = seq.length();
    } else {
      byte[] chars = seq.toString().getBytes(charset);
      this.setBytes(index, chars);
      writtenBytes = chars.length;
    }
    return this;
  }

  @Override
  public boolean readBoolean() {
    return readByte() != 0;
  }

  @Override
  public byte readByte() {
    checkReadableBytes(1);
    long i = readerIndex;
    byte b = getByte(i);
    readerIndex = i + 1;
    return b;
  }

  @Override
  public short readUnsignedByte() {
    return (short) (readByte() & 0xFF);
  }

  @Override
  public short readShort() {
    checkReadableBytes(2);
    short v = getShort(readerIndex);
    readerIndex += 2;
    return v;
  }

  @Override
  public short readShortLE() {
    checkReadableBytes(2);
    short v = getShortLE(readerIndex);
    readerIndex += 2;
    return v;
  }

  @Override
  public int readUnsignedShort() {
    return readShort() & 0xFFFF;
  }

  @Override
  public int readUnsignedShortLE() {
    return readShortLE() & 0xFFFF;
  }

  @Override
  public int readInt() {
    checkReadableBytes(4);
    int v = getInt(readerIndex);
    readerIndex += 4;
    return v;
  }

  @Override
  public int readIntLE() {
    checkReadableBytes(4);
    int v = getIntLE(readerIndex);
    readerIndex += 4;
    return v;
  }

  @Override
  public long readUnsignedInt() {
    return readInt() & 0xFFFFFFFFL;
  }

  @Override
  public long readUnsignedIntLE() {
    return readIntLE() & 0xFFFFFFFFL;
  }

  @Override
  public float readFloat() {
    return Float.intBitsToFloat(readInt());
  }

  @Override
  public float readFloatLE() {
    return Float.intBitsToFloat(this.readIntLE());
  }

  @Override
  public double readDouble() {
    return Double.longBitsToDouble(readLong());
  }

  @Override
  public double readDoubleLE() {
    return Double.longBitsToDouble(this.readLongLE());
  }

  @Override
  public long readLong() {
    checkReadableBytes(8);
    long v = getLong(readerIndex);
    readerIndex += 8;
    return v;
  }

  @Override
  public long readLongLE() {
    checkReadableBytes(8);
    long v = getLongLE(readerIndex);
    readerIndex += 8;
    return v;
  }

  @Override
  public Memory readBytes(Memory dst) {
    readBytes(dst, dst.writableBytes());
    return this;
  }

  @Override
  public Memory readBytes(Memory dst, long length) {
    return readBytes(dst, 0, length);
  }

  @Override
  public Memory readBytes(Memory dst, long dstIndex, long length) {
    checkReadableBytes(length);
    getBytes(readerIndex, dst, dstIndex, length);
    readerIndex += length;
    return this;
  }

  @Override
  public Memory readBytes(byte[] dst) {
    readBytes(dst, 0, dst.length);
    return this;
  }

  @Override
  public Memory readBytes(byte[] dst, long dstIndex, long length) {
    checkReadableBytes(length);
    getBytes(readerIndex, dst, dstIndex, length);
    readerIndex += length;
    return this;
  }

  @Override
  public Memory skipBytes(long length) {
    checkReadableBytes(length);
    readerIndex += length;
    return this;
  }

  @Override
  public CharSequence readCharSequence(long length, Charset charset) {
    CharSequence sequence = this.getCharSequence(readerIndex, length, charset);
    readerIndex += length;
    return sequence;
  }

  @Override
  public Memory writeBoolean(boolean value) {
    writeByte(value ? 1 : 0);
    return this;
  }

  @Override
  public Memory writeByte(int value) {
    checkWritableBytes(1);
    setByte(writerIndex++, value);
    return this;
  }

  @Override
  public Memory writeShort(int value) {
    checkWritableBytes(2);
    setShort(writerIndex, value);
    writerIndex += 2;
    return this;
  }

  @Override
  public Memory writeShortLE(int value) {
    checkWritableBytes(2);
    setShortLE(writerIndex, value);
    writerIndex += 2;
    return this;
  }

  @Override
  public Memory writeInt(int value) {
    checkWritableBytes(4);
    setInt(writerIndex, value);
    writerIndex += 4;
    return this;
  }

  @Override
  public Memory writeIntLE(int value) {
    checkWritableBytes(4);
    setIntLE(writerIndex, value);
    writerIndex += 4;
    return this;
  }

  @Override
  public Memory writeLong(long value) {
    checkWritableBytes(8);
    setLong(writerIndex, value);
    writerIndex += 8;
    return this;
  }

  @Override
  public Memory writeLongLE(long value) {
    checkWritableBytes(8);
    setLongLE(writerIndex, value);
    writerIndex += 8;
    return this;
  }

  @Override
  public Memory writeFloat(float value) {
    writeInt(Float.floatToRawIntBits(value));
    return this;
  }

  @Override
  public Memory writeFloatLE(float value) {
    return writeIntLE(Float.floatToRawIntBits(value));
  }

  @Override
  public Memory writeDoubleLE(double value) {
    return writeLongLE(Double.doubleToRawLongBits(value));
  }

  @Override
  public Memory writeDouble(double value) {
    writeLong(Double.doubleToRawLongBits(value));
    return this;
  }

  @Override
  public Memory writeBytes(Memory src) {
    writeBytes(src, src.readableBytes());
    return this;
  }

  @Override
  public Memory writeBytes(Memory src, long length) {
    return writeBytes(src, 0, length);
  }

  @Override
  public Memory writeBytes(Memory src, long srcIndex, long length) {
    ensureWritable(length);
    setBytes(writerIndex, src, srcIndex, length);
    writerIndex += length;
    return this;
  }

  @Override
  public Memory writeBytes(byte[] src) {
    writeBytes(src, 0, src.length);
    return this;
  }

  @Override
  public Memory writeBytes(byte[] src, long srcIndex, long length) {
    ensureWritable(length);
    setBytes(writerIndex, src, srcIndex, length);
    writerIndex += length;
    return this;
  }

  @Override
  public Memory writeCharSequence(CharSequence sequence, Charset charset) {
    this.setCharSequence(writerIndex, sequence, charset);
    writerIndex += writtenBytes;
    return this;
  }

  @Override
  public Memory copy() {
    return copy(0, capacity());
  }

  @Override
  public Memory slice() {
    return slice(readerIndex, readableBytes());
  }

  private long calculateNewCapacity(long minNewCapacity, long maxCapacity) {
    if (minNewCapacity < 0) {
      throw new IllegalArgumentException("minNewCapacity: " + minNewCapacity + " (expected: 0+)");
    }
    if (minNewCapacity > maxCapacity) {
      throw new IllegalArgumentException(
          String.format(
              "minNewCapacity: %d (expected: not greater than maxCapacity(%d)",
              minNewCapacity, maxCapacity));
    }
    final int threshold = 1048576 * 4; // 4 MiB page

    if (minNewCapacity == threshold) {
      return threshold;
    }

    // If over threshold, do not double but just increase by threshold.
    if (minNewCapacity > threshold) {
      long newCapacity = minNewCapacity / threshold * threshold;
      if (newCapacity > maxCapacity - threshold) {
        newCapacity = maxCapacity;
      } else {
        newCapacity += threshold;
      }
      return newCapacity;
    }

    // Not over threshold. Double up to 4 MiB, starting from 64.
    long newCapacity = 64;
    while (newCapacity < minNewCapacity) {
      newCapacity <<= 1;
    }

    return Math.min(newCapacity, maxCapacity);
  }

  private void checkWritableBytes(long minWritableBytes) {
    if (minWritableBytes <= writableBytes()) {
      return;
    }

    if (minWritableBytes > maxCapacity - writerIndex()) {
      throw new IndexOutOfBoundsException(
          String.format(
              "writerIndex(%d) + minWritableBytes(%d) exceeds maxCapacity(%d): %s",
              writerIndex(), minWritableBytes, maxCapacity, this));
    }

    // Normalize the current capacity to the power of 2.
    long newCapacity = calculateNewCapacity(writerIndex() + minWritableBytes, maxCapacity);

    // Adjust to the new capacity.
    capacity(newCapacity);
  }

  private void checkReadableBytes(long minimumReadableBytes) {
    if (minimumReadableBytes < 0) {
      throw new IllegalArgumentException(
          "minimumReadableBytes: " + minimumReadableBytes + " (expected: >= 0)");
    }
    if (readerIndex() > writerIndex() - minimumReadableBytes) {
      throw new IndexOutOfBoundsException(
          String.format(
              "readerIndex(%d) + length(%d) exceeds writerIndex(%d): %s",
              readerIndex(), minimumReadableBytes, writerIndex(), this));
    }
  }

  void checkIndex(long index, long fieldLength) {
    if (isOutOfBounds(index, fieldLength, capacity())) {
      throw new IndexOutOfBoundsException(
          String.format(
              "index: %d, length: %d (expected: range(0, %d))", index, fieldLength, capacity()));
    }
  }

  boolean isOutOfBounds(long index, long length, long capacity) {
    return (index | length | (index + length) | (capacity - (index + length))) < 0;
  }

  protected void checkNewCapacity(long newCapacity) {
    if (newCapacity < 0 || newCapacity > maxCapacity()) {
      throw new IllegalArgumentException(
          "newCapacity: " + newCapacity + " (expected: 0-" + maxCapacity() + ')');
    }
  }

  @Override
  public String toString() {
    return Strings.toStringBuilder(this)
        .add("capacity", capacity)
        .add("maxCapacity", maxCapacity)
        .add("writtenBytes", writtenBytes)
        .add("readerIndex", readerIndex)
        .add("writerIndex", writerIndex)
        .add("markedReaderIndex", markedReaderIndex)
        .add("markedWriterIndex", markedWriterIndex)
        .add("freed", freed)
        .toString();
  }
}
