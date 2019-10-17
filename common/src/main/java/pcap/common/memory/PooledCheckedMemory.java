/** This code is licenced under the GPL version 2. */
package pcap.common.memory;

import pcap.common.annotation.Inclubating;
import pcap.common.util.Validate;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
@Inclubating
class PooledCheckedMemory extends CheckedMemory implements Pooled {

  PooledCheckedMemory(long address, int capacity, int maxCapacity) {
    super(address, capacity, maxCapacity);
  }

  PooledCheckedMemory(
      long address, int capacity, int maxCapacity, int readerIndex, int writerIndex) {
    super(address, capacity, maxCapacity, readerIndex, writerIndex);
  }

  @Override
  public PooledCheckedMemory capacity(int newCapacity) {
    Validate.notIllegalArgument(
        newCapacity <= maxCapacity,
        new IllegalArgumentException(
            String.format("newCapacity < maxCapacity: %s <= %s", newCapacity, maxCapacity)));
    this.capacity = newCapacity;
    return this;
  }

  @Override
  public PooledCheckedMemory copy(int index, int length) {
    ensureAccessible(index, length);
    long newAddress = ACCESSOR.allocate(length);
    PooledCheckedMemory memory =
        new PooledCheckedMemory(newAddress, length, maxCapacity, readerIndex(), writerIndex());
    if (length != 0) {
      memory.setBytes(0, this, index, length);
    }
    return memory;
  }

  @Override
  public PooledSlicedCheckedMemory slice(int index, int length) {
    ensureAccessible(index, length);
    return new PooledSlicedCheckedMemory(
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
  public PooledCheckedMemory duplicate() {
    ensureAccessible();
    PooledCheckedMemory memory =
        new PooledCheckedMemory(address, capacity, maxCapacity, readerIndex(), writerIndex());
    return memory;
  }

  @Override
  public void release() {
    Memories.offer(this);
  }
}
