/** This code is licenced under the GPL version 2. */
package pcap.common.memory;

import pcap.common.annotation.Inclubating;
import pcap.common.util.Validate;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
@Inclubating
class PooledUncheckedMemory extends UncheckedMemory {

  PooledUncheckedMemory(long address, int capacity, int maxCapacity) {
    super(address, capacity, maxCapacity);
  }

  PooledUncheckedMemory(
      long address, int capacity, int maxCapacity, int readerIndex, int writerIndex) {
    super(address, capacity, maxCapacity, readerIndex, writerIndex);
  }

  @Override
  public PooledUncheckedMemory capacity(int newCapacity) {
    Validate.notIllegalArgument(
        newCapacity <= maxCapacity,
        new IllegalArgumentException(
            String.format("newCapacity <= maxCapacity: %s <= %s", newCapacity, maxCapacity)));
    this.capacity = newCapacity;
    return this;
  }

  @Override
  public PooledUncheckedMemory copy(int index, int length) {
    long newAddress = ACCESSOR.allocate(length);
    PooledUncheckedMemory memory =
        new PooledUncheckedMemory(newAddress, length, maxCapacity, readerIndex(), writerIndex());
    if (length != 0) {
      memory.setBytes(0, this, index, length);
    }
    return memory;
  }

  @Override
  public PooledSlicedUncheckedMemory slice(int index, int length) {
    return new PooledSlicedUncheckedMemory(
        buffer,
        address,
        capacity,
        address + index,
        length,
        maxCapacity,
        readerIndex() - index,
        writerIndex() - index);
  }

  @Override
  public PooledUncheckedMemory duplicate() {
    PooledUncheckedMemory memory =
        new PooledUncheckedMemory(address, capacity, maxCapacity, readerIndex(), writerIndex());
    return memory;
  }

  @Override
  public void release() {
    Memories.offer(this);
  }
}
