/** This code is licenced under the GPL version 2. */
package pcap.common.memory;

import java.nio.BufferOverflowException;
import java.nio.ByteBuffer;
import java.util.concurrent.atomic.AtomicIntegerFieldUpdater;
import pcap.common.annotation.Inclubating;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
@Inclubating
public abstract class Stream extends AbstractMemory<Memory[]> {

  final AtomicIntegerFieldUpdater<Stream> positinUpdater =
      AtomicIntegerFieldUpdater.newUpdater(Stream.class, "position");

  final AtomicIntegerFieldUpdater<Stream> baseIndexUpdater =
      AtomicIntegerFieldUpdater.newUpdater(Stream.class, "baseIndex");

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
    baseIndexUpdater.set(this, baseIndex);
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
      return new CheckedStream(0, memories, capacity, maxCapacity, readerIndex, writerIndex);
    } else {
      return new UncheckedStream(0, memories, capacity, maxCapacity, readerIndex, writerIndex);
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
    positinUpdater.set(this, 0);
    for (Memory memory : this.buffer) {
      positinUpdater.addAndGet(this, memory.capacity());
      if (index < this.position) {
        return memory;
      }
    }
    throw new BufferOverflowException();
  }
}
