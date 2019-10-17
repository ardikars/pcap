package pcap.common.memory;

import pcap.common.annotation.Inclubating;

import java.nio.BufferOverflowException;
import java.nio.ByteBuffer;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
@Inclubating
public abstract class Stream extends AbstractMemory<Memory[]> {

  protected volatile int position;
  protected volatile int baseIndex;

  protected Stream(
      int baseIndex,
      Memory[] buffer,
      int capacity,
      int maxCapacity,
      int readerIndex,
      int writerIndex) {
    super(buffer, capacity, maxCapacity, readerIndex, writerIndex);
    this.baseIndex = baseIndex;
  }

  public static Stream stream(Memory[] memories, boolean checked) {
    int capacity = 0;
    int maxCapacity = 0;
    int readerIndex = 0;
    int writerIndex = 0;
    for (Memory memory : memories) {
      if (memory instanceof Stream) {
        throw new UnsupportedOperationException();
      }
      capacity += memory.capacity();
      maxCapacity += memory.maxCapacity();
      readerIndex += memory.readerIndex();
      writerIndex += memory.writerIndex();
    }
    if (checked) {
      return new CheckedStream(
          0, memories, capacity, maxCapacity, readerIndex, writerIndex);
    } else {
      return new UncheckedStream(
          0, memories, capacity, maxCapacity, readerIndex, writerIndex);
    }
  }

  @Override
  public Memory capacity(int newCapacity) {
    throw new UnsupportedOperationException();
  }

  @Override
  public Memory copy(int index, int length) {
    throw new UnsupportedOperationException();
  }

  @Override
  public Memory duplicate() {
    throw new UnsupportedOperationException();
  }

  @Override
  public ByteBuffer nioBuffer() {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean isDirect() {
    throw new UnsupportedOperationException();
  }

  @Override
  public long memoryAddress() {
    throw new UnsupportedOperationException();
  }

  protected int index(int index, Memory memory) {
    return baseIndex + position - index + memory.capacity();
  }

  protected Memory getMemory(int index) {
    this.position = 0;
    for (Memory memory : this.buffer) {
      this.position += memory.capacity();
      if (index < this.position) {
        return memory;
      }
    }
    throw new BufferOverflowException();
  }
}
