package pcap.common.memory;

import pcap.common.annotation.Inclubating;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
@Inclubating
class CheckedStream extends Stream {

  CheckedStream(
      int baseIndex,
      Memory[] buffer,
      int capacity,
      int maxCapacity,
      int readerIndex,
      int writerIndex) {
    super(baseIndex, buffer, capacity, maxCapacity, readerIndex, writerIndex);
  }

  @Override
  public byte getByte(int index) {
    Memory memory = getMemory(index);
    return memory.getByte(index(index, memory));
  }

  @Override
  public short getShort(int index) {
    Memory memory = getMemory(index);
    return memory.getShort(index(index, memory));
  }

  @Override
  public short getShortLE(int index) {
    Memory memory = getMemory(index);
    return memory.getShortLE(index(index, memory));
  }

  @Override
  public int getInt(int index) {
    Memory memory = getMemory(index);
    return memory.getInt(index(index, memory));
  }

  @Override
  public int getIntLE(int index) {
    Memory memory = getMemory(index);
    return memory.getIntLE(index(index, memory));
  }

  @Override
  public long getLong(int index) {
    Memory memory = getMemory(index);
    return memory.getLong(index(index, memory));
  }

  @Override
  public long getLongLE(int index) {
    Memory memory = getMemory(index);
    return memory.getLongLE(index(index, memory));
  }

  @Override
  public Memory getBytes(int index, Memory dst, int dstIndex, int length) {
    Memory memory = getMemory(index);
    return memory.getBytes(index(index, memory), dst, dstIndex, length);
  }

  @Override
  public Memory getBytes(int index, byte[] dst, int dstIndex, int length) {
    Memory memory = getMemory(index);
    return memory.getBytes(index(index, memory), dst, dstIndex, length);
  }

  @Override
  public Memory setByte(int index, int value) {
    Memory memory = getMemory(index);
    return memory.setByte(index(index, memory), value);
  }

  @Override
  public Memory setShort(int index, int value) {
    Memory memory = getMemory(index);
    return memory.setShort(index(index, memory), value);
  }

  @Override
  public Memory setShortLE(int index, int value) {
    Memory memory = getMemory(index);
    return memory.setShortLE(index(index, memory), value);
  }

  @Override
  public Memory setInt(int index, int value) {
    Memory memory = getMemory(index);
    return memory.setInt(index(index, memory), value);
  }

  @Override
  public Memory setIntLE(int index, int value) {
    Memory memory = getMemory(index);
    return memory.setIntLE(index(index, memory), value);
  }

  @Override
  public Memory setLong(int index, long value) {
    Memory memory = getMemory(index);
    return memory.setLong(index(index, memory), value);
  }

  @Override
  public Memory setLongLE(int index, long value) {
    Memory memory = getMemory(index);
    return memory.setLongLE(index(index, memory), value);
  }

  @Override
  public Memory setBytes(int index, Memory src, int srcIndex, int length) {
    Memory memory = getMemory(index);
    return memory.setBytes(index(index, memory), src, srcIndex, length);
  }

  @Override
  public Memory setBytes(int index, byte[] src, int srcIndex, int length) {
    Memory memory = getMemory(index);
    return memory.setBytes(index(index, memory), src, srcIndex, length);
  }

  @Override
  public Memory slice(int index, int length) {
    return new SlicedCheckedStream(
        index, buffer, capacity, maxCapacity, readerIndex(), writerIndex());
  }

  @Override
  public void release() {
    for (Memory memory : buffer) {
      memory.release();
    }
  }
}
