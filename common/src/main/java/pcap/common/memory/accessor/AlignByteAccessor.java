/** This code is licenced under the GPL version 2. */
package pcap.common.memory.accessor;

import pcap.common.annotation.Inclubating;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
@Inclubating
public class AlignByteAccessor extends AbstractByteAccessor {

  @Override
  public short getShort(byte[] buffer, int index) {
    return (short)
        (UNSAFE.getByte(buffer, (long) BYTE_ARRAY_OFFSET + index) << 8
            | UNSAFE.getByte(buffer, (long) BYTE_ARRAY_OFFSET + index + 1) & 0xff);
  }

  @Override
  public short getShortLE(byte[] buffer, int index) {
    return (short)
        (UNSAFE.getByte(buffer, (long) BYTE_ARRAY_OFFSET + index) & 0xff
            | UNSAFE.getByte(buffer, (long) BYTE_ARRAY_OFFSET + index + 1) << 8);
  }

  @Override
  public int getInt(byte[] buffer, int index) {
    return UNSAFE.getByte(buffer, (long) BYTE_ARRAY_OFFSET + index) << 24
        | (UNSAFE.getByte(buffer, (long) BYTE_ARRAY_OFFSET + index + 1) & 0xff) << 16
        | (UNSAFE.getByte(buffer, (long) BYTE_ARRAY_OFFSET + index + 2) & 0xff) << 8
        | UNSAFE.getByte(buffer, (long) BYTE_ARRAY_OFFSET + index + 3) & 0xff;
  }

  @Override
  public int getIntLE(byte[] buffer, int index) {
    return UNSAFE.getByte(buffer, (long) BYTE_ARRAY_OFFSET + index) & 0xff
        | (UNSAFE.getByte(buffer, (long) BYTE_ARRAY_OFFSET + index + 1) & 0xff) << 8
        | (UNSAFE.getByte(buffer, (long) BYTE_ARRAY_OFFSET + index + 2) & 0xff) << 16
        | UNSAFE.getByte(buffer, (long) BYTE_ARRAY_OFFSET + index + 3) << 24;
  }

  @Override
  public long getLong(byte[] buffer, int index) {
    return ((long) UNSAFE.getByte(buffer, (long) BYTE_ARRAY_OFFSET + index)) << 56
        | (UNSAFE.getByte(buffer, (long) BYTE_ARRAY_OFFSET + index + 1) & 0xffL) << 48
        | (UNSAFE.getByte(buffer, (long) BYTE_ARRAY_OFFSET + index + 2) & 0xffL) << 40
        | (UNSAFE.getByte(buffer, (long) BYTE_ARRAY_OFFSET + index + 3) & 0xffL) << 32
        | (UNSAFE.getByte(buffer, (long) BYTE_ARRAY_OFFSET + index + 4) & 0xffL) << 24
        | (UNSAFE.getByte(buffer, (long) BYTE_ARRAY_OFFSET + index + 5) & 0xffL) << 16
        | (UNSAFE.getByte(buffer, (long) BYTE_ARRAY_OFFSET + index + 6) & 0xffL) << 8
        | (UNSAFE.getByte(buffer, (long) BYTE_ARRAY_OFFSET + index + 7)) & 0xffL;
  }

  @Override
  public long getLongLE(byte[] buffer, int index) {
    return UNSAFE.getByte(buffer, (long) BYTE_ARRAY_OFFSET + index) & 0xffL
        | (UNSAFE.getByte(buffer, (long) BYTE_ARRAY_OFFSET + index + 1) & 0xffL) << 8
        | (UNSAFE.getByte(buffer, (long) BYTE_ARRAY_OFFSET + index + 2) & 0xffL) << 16
        | (UNSAFE.getByte(buffer, (long) BYTE_ARRAY_OFFSET + index + 3) & 0xffL) << 24
        | (UNSAFE.getByte(buffer, (long) BYTE_ARRAY_OFFSET + index + 4) & 0xffL) << 32
        | (UNSAFE.getByte(buffer, (long) BYTE_ARRAY_OFFSET + index + 5) & 0xffL) << 40
        | (UNSAFE.getByte(buffer, (long) BYTE_ARRAY_OFFSET + index + 6) & 0xffL) << 48
        | ((long) UNSAFE.getByte(buffer, (long) BYTE_ARRAY_OFFSET + index + 7)) << 56;
  }

  @Override
  public void setShort(byte[] buffer, int index, int val) {
    UNSAFE.putByte(buffer, BYTE_ARRAY_OFFSET + index, (byte) (val >>> 8));
    UNSAFE.putByte(buffer, BYTE_ARRAY_OFFSET + index + 1, (byte) val);
  }

  @Override
  public void setShortLE(byte[] buffer, int index, int val) {
    UNSAFE.putByte(buffer, BYTE_ARRAY_OFFSET + index, (byte) val);
    UNSAFE.putByte(buffer, BYTE_ARRAY_OFFSET + index + 1, (byte) (val >>> 8));
  }

  @Override
  public void setInt(byte[] buffer, int index, int val) {
    UNSAFE.putByte(buffer, (long) BYTE_ARRAY_OFFSET + index, (byte) (val >>> 24));
    UNSAFE.putByte(buffer, (long) BYTE_ARRAY_OFFSET + index + 1, (byte) (val >>> 16));
    UNSAFE.putByte(buffer, (long) BYTE_ARRAY_OFFSET + index + 2, (byte) (val >>> 8));
    UNSAFE.putByte(buffer, (long) BYTE_ARRAY_OFFSET + index + 3, (byte) val);
  }

  @Override
  public void setIntLE(byte[] buffer, int index, int val) {
    UNSAFE.putByte(buffer, (long) BYTE_ARRAY_OFFSET + index, (byte) val);
    UNSAFE.putByte(buffer, (long) BYTE_ARRAY_OFFSET + index + 1, (byte) (val >>> 8));
    UNSAFE.putByte(buffer, (long) BYTE_ARRAY_OFFSET + index + 2, (byte) (val >>> 16));
    UNSAFE.putByte(buffer, (long) BYTE_ARRAY_OFFSET + index + 3, (byte) (val >>> 24));
  }

  @Override
  public void setLong(byte[] buffer, int index, long val) {
    UNSAFE.putByte(buffer, (long) BYTE_ARRAY_OFFSET + index, (byte) (val >>> 56));
    UNSAFE.putByte(buffer, (long) BYTE_ARRAY_OFFSET + index + 1, (byte) (val >>> 48));
    UNSAFE.putByte(buffer, (long) BYTE_ARRAY_OFFSET + index + 2, (byte) (val >>> 40));
    UNSAFE.putByte(buffer, (long) BYTE_ARRAY_OFFSET + index + 3, (byte) (val >>> 32));
    UNSAFE.putByte(buffer, (long) BYTE_ARRAY_OFFSET + index + 4, (byte) (val >>> 24));
    UNSAFE.putByte(buffer, (long) BYTE_ARRAY_OFFSET + index + 5, (byte) (val >>> 16));
    UNSAFE.putByte(buffer, (long) BYTE_ARRAY_OFFSET + index + 6, (byte) (val >>> 8));
    UNSAFE.putByte(buffer, (long) BYTE_ARRAY_OFFSET + index + 7, (byte) val);
  }

  @Override
  public void setLongLE(byte[] buffer, int index, long val) {
    UNSAFE.putByte(buffer, (long) BYTE_ARRAY_OFFSET + index, (byte) val);
    UNSAFE.putByte(buffer, (long) BYTE_ARRAY_OFFSET + index + 1, (byte) (val >>> 8));
    UNSAFE.putByte(buffer, (long) BYTE_ARRAY_OFFSET + index + 2, (byte) (val >>> 16));
    UNSAFE.putByte(buffer, (long) BYTE_ARRAY_OFFSET + index + 3, (byte) (val >>> 24));
    UNSAFE.putByte(buffer, (long) BYTE_ARRAY_OFFSET + index + 4, (byte) (val >>> 32));
    UNSAFE.putByte(buffer, (long) BYTE_ARRAY_OFFSET + index + 5, (byte) (val >>> 40));
    UNSAFE.putByte(buffer, (long) BYTE_ARRAY_OFFSET + index + 6, (byte) (val >>> 48));
    UNSAFE.putByte(buffer, (long) BYTE_ARRAY_OFFSET + index + 7, (byte) (val >>> 56));
  }
}
