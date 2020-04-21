/** This code is licenced under the GPL version 2. */
package pcap.common.memory.accessor;

import java.nio.ByteBuffer;
import pcap.common.annotation.Inclubating;
import pcap.common.internal.ByteBufferHelper;
import pcap.common.internal.Unsafe;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
@Inclubating
abstract class AbstractMemoryAcessor implements MemoryAccessor {

  static final Unsafe UNSAFE = Unsafe.UNSAFE;

  static final int BYTE_ARRAY_OFFSET = UNSAFE.arrayBaseOffset(byte[].class);

  @Override
  public long allocate(int size) {
    return UNSAFE.allocateMemory(size);
  }

  @Override
  public long reallocate(long addr, int size) {
    return UNSAFE.reallocateMemory(addr, size);
  }

  @Override
  public void deallocate(long addr) {
    UNSAFE.freeMemory(addr);
  }

  @Override
  public ByteBuffer nioBuffer(long addr, int size) {
    return ByteBufferHelper.wrapDirectByteBuffer(addr, size);
  }

  @Override
  public byte getByte(long addr) {
    return UNSAFE.getByte(addr);
  }

  @Override
  public void setByte(long addr, int val) {
    UNSAFE.putByte(addr, (byte) val);
  }

  @Override
  public void getBytes(long srcAddr, int index, long dstAddr, int dstIndex, int size) {
    UNSAFE.copyMemory(null, srcAddr + index, null, dstAddr + dstIndex, size);
  }

  @Override
  public void getBytes(long srcAddr, int index, byte[] dst, int dstIndex, int size) {
    UNSAFE.copyMemory(null, srcAddr + (long) index, dst, (long) BYTE_ARRAY_OFFSET + dstIndex, size);
  }

  @Override
  public void setBytes(long dstAddr, int index, long srcAddr, int srcIndex, int size) {
    UNSAFE.copyMemory(null, srcAddr + srcIndex, null, dstAddr + index, size);
  }

  @Override
  public void setBytes(long dstAddr, int index, byte[] src, int srcIndex, int size) {
    UNSAFE.copyMemory(src, (long) BYTE_ARRAY_OFFSET + srcIndex, null, dstAddr + index, size);
  }
}
