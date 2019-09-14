/** This code is licenced under the GPL version 2. */
package pcap.common.memory.accessor;

import pcap.common.annotation.Inclubating;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
@Inclubating
class AlignMemoryAcessor extends AbstractMemoryAcessor {

  @Override
  public short getShort(long addr) {
    return (short) (UNSAFE.getByte(addr) << 8 | UNSAFE.getByte(addr + 1) & 0xff);
  }

  @Override
  public short getShortLE(long addr) {
    return (short) (UNSAFE.getByte(addr) & 0xff | UNSAFE.getByte(addr + 1) << 8);
  }

  @Override
  public int getInt(long addr) {
    return UNSAFE.getByte(addr) << 24
        | (UNSAFE.getByte(addr + 1) & 0xff) << 16
        | (UNSAFE.getByte(addr + 2) & 0xff) << 8
        | UNSAFE.getByte(addr + 3) & 0xff;
  }

  @Override
  public int getIntLE(long addr) {
    return UNSAFE.getByte(addr) & 0xff
        | (UNSAFE.getByte(addr + 1) & 0xff) << 8
        | (UNSAFE.getByte(addr + 2) & 0xff) << 16
        | UNSAFE.getByte(addr + 3) << 24;
  }

  @Override
  public long getLong(long addr) {
    return ((long) UNSAFE.getByte(addr)) << 56
        | (UNSAFE.getByte(addr + 1) & 0xffL) << 48
        | (UNSAFE.getByte(addr + 2) & 0xffL) << 40
        | (UNSAFE.getByte(addr + 3) & 0xffL) << 32
        | (UNSAFE.getByte(addr + 4) & 0xffL) << 24
        | (UNSAFE.getByte(addr + 5) & 0xffL) << 16
        | (UNSAFE.getByte(addr + 6) & 0xffL) << 8
        | (UNSAFE.getByte(addr + 7)) & 0xffL;
  }

  @Override
  public long getLongLE(long addr) {
    return (UNSAFE.getByte(addr)) & 0xffL
        | (UNSAFE.getByte(addr + 1) & 0xffL) << 8
        | (UNSAFE.getByte(addr + 2) & 0xffL) << 16
        | (UNSAFE.getByte(addr + 3) & 0xffL) << 24
        | (UNSAFE.getByte(addr + 4) & 0xffL) << 32
        | (UNSAFE.getByte(addr + 5) & 0xffL) << 40
        | (UNSAFE.getByte(addr + 6) & 0xffL) << 48
        | ((long) UNSAFE.getByte(addr + 7)) << 56;
  }

  @Override
  public void setShort(long addr, int val) {
    UNSAFE.putByte(addr, (byte) (val >>> 8));
    UNSAFE.putByte(addr + 1, (byte) val);
  }

  @Override
  public void setShortLE(long addr, int val) {
    UNSAFE.putByte(addr, (byte) val);
    UNSAFE.putByte(addr + 1, (byte) (val >>> 8));
  }

  @Override
  public void setInt(long addr, int val) {
    UNSAFE.putByte(addr, (byte) (val >>> 24));
    UNSAFE.putByte(addr + 1, (byte) (val >>> 16));
    UNSAFE.putByte(addr + 2, (byte) (val >>> 8));
    UNSAFE.putByte(addr + 3, (byte) val);
  }

  @Override
  public void setIntLE(long addr, int val) {
    UNSAFE.putByte(addr, (byte) val);
    UNSAFE.putByte(addr + 1, (byte) (val >>> 8));
    UNSAFE.putByte(addr + 2, (byte) (val >>> 16));
    UNSAFE.putByte(addr + 3, (byte) (val >>> 24));
  }

  @Override
  public void setLong(long addr, long val) {
    UNSAFE.putByte(addr, (byte) (val >>> 56));
    UNSAFE.putByte(addr + 1, (byte) (val >>> 48));
    UNSAFE.putByte(addr + 2, (byte) (val >>> 40));
    UNSAFE.putByte(addr + 3, (byte) (val >>> 32));
    UNSAFE.putByte(addr + 4, (byte) (val >>> 24));
    UNSAFE.putByte(addr + 5, (byte) (val >>> 16));
    UNSAFE.putByte(addr + 6, (byte) (val >>> 8));
    UNSAFE.putByte(addr + 7, (byte) val);
  }

  @Override
  public void setLongLE(long addr, long val) {
    UNSAFE.putByte(addr, (byte) val);
    UNSAFE.putByte(addr + 1, (byte) (val >>> 8));
    UNSAFE.putByte(addr + 2, (byte) (val >>> 16));
    UNSAFE.putByte(addr + 3, (byte) (val >>> 24));
    UNSAFE.putByte(addr + 4, (byte) (val >>> 32));
    UNSAFE.putByte(addr + 5, (byte) (val >>> 40));
    UNSAFE.putByte(addr + 6, (byte) (val >>> 48));
    UNSAFE.putByte(addr + 7, (byte) (val >>> 56));
  }
}
