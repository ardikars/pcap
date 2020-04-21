/** This code is licenced under the GPL version 2. */
package pcap.common.memory.accessor;

import java.nio.ByteBuffer;
import pcap.common.annotation.Inclubating;
import pcap.common.internal.Unsafe;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
@Inclubating
abstract class AbstractByteAccessor implements ByteAccessor {

  static final Unsafe UNSAFE = Unsafe.UNSAFE;

  static final int BYTE_ARRAY_OFFSET = UNSAFE.arrayBaseOffset(byte[].class);

  @Override
  public byte[] allocate(int size) {
    return new byte[size];
  }

  @Override
  public byte getByte(byte[] buffer, int index) {
    return buffer[index];
  }

  @Override
  public ByteBuffer nioBuffer(byte[] buffer, int offset, int length) {
    return ByteBuffer.wrap(buffer, offset, length);
  }

  @Override
  public void getBytes(byte[] srcBuf, int index, byte[] dstBuf, int dstIndex, int size) {
    System.arraycopy(srcBuf, index, dstBuf, dstIndex, size);
  }

  @Override
  public void setByte(byte[] buffer, int index, int val) {
    buffer[index] = (byte) val;
  }

  @Override
  public void setBytes(byte[] dstBuf, int index, byte[] srcBuf, int srcIndex, int size) {
    System.arraycopy(srcBuf, srcIndex, dstBuf, index, size);
  }
}
