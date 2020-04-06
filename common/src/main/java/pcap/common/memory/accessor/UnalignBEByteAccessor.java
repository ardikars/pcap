/** This code is licenced under the GPL version 2. */
package pcap.common.memory.accessor;

import pcap.common.annotation.Inclubating;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
@Inclubating
public class UnalignBEByteAccessor extends AbstractByteAccessor {

  @Override
  public short getShort(byte[] buffer, int index) {
    return UNSAFE.getShort(buffer, (long) BYTE_ARRAY_OFFSET + index);
  }

  @Override
  public short getShortLE(byte[] buffer, int index) {
    return Short.reverseBytes(UNSAFE.getShort(buffer, (long) BYTE_ARRAY_OFFSET + index));
  }

  @Override
  public int getInt(byte[] buffer, int index) {
    return UNSAFE.getInt(buffer, (long) BYTE_ARRAY_OFFSET + index);
  }

  @Override
  public int getIntLE(byte[] buffer, int index) {
    return Integer.reverseBytes(UNSAFE.getInt(buffer, (long) BYTE_ARRAY_OFFSET + index));
  }

  @Override
  public long getLong(byte[] buffer, int index) {
    return UNSAFE.getLong(buffer, (long) BYTE_ARRAY_OFFSET + index);
  }

  @Override
  public long getLongLE(byte[] buffer, int index) {
    return Long.reverseBytes(UNSAFE.getLong(buffer, (long) BYTE_ARRAY_OFFSET + index));
  }

  @Override
  public void setShort(byte[] buffer, int index, int val) {
    UNSAFE.putShort(buffer, (long) BYTE_ARRAY_OFFSET + index, (short) val);
  }

  @Override
  public void setShortLE(byte[] buffer, int index, int val) {
    UNSAFE.putShort(buffer, (long) BYTE_ARRAY_OFFSET + index, Short.reverseBytes((short) val));
  }

  @Override
  public void setInt(byte[] buffer, int index, int val) {
    UNSAFE.putInt(buffer, (long) BYTE_ARRAY_OFFSET + index, val);
  }

  @Override
  public void setIntLE(byte[] buffer, int index, int val) {
    UNSAFE.putInt(buffer, (long) BYTE_ARRAY_OFFSET + index, Integer.reverseBytes(val));
  }

  @Override
  public void setLong(byte[] buffer, int index, long val) {
    UNSAFE.putLong(buffer, (long) BYTE_ARRAY_OFFSET + index, val);
  }

  @Override
  public void setLongLE(byte[] buffer, int index, long val) {
    UNSAFE.putLong(buffer, (long) BYTE_ARRAY_OFFSET + index, Long.reverseBytes(val));
  }
}
