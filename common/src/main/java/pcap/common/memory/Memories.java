/** This code is licenced under the GPL version 2. */
package pcap.common.memory;

import java.nio.ByteBuffer;
import pcap.common.annotation.Inclubating;
import pcap.common.memory.internal.allocator.DirectMemoryAllocator;
import pcap.common.memory.internal.allocator.HeapMemoryAllocator;
import pcap.common.memory.internal.allocator.PooledDirectMemoryAllocator;
import pcap.common.memory.internal.allocator.PooledHeapMemoryAllocator;
import pcap.common.memory.internal.nio.DirectByteBuffer;
import pcap.common.util.Hexs;
import pcap.common.util.Validate;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
@Inclubating
public final class Memories {

  /**
   * Get default memory allocator.
   *
   * @return returns default memory allocator.
   */
  public static MemoryAllocator allocator() {
    return new HeapMemoryAllocator();
  }

  /**
   * Get direct memory allocator.
   *
   * @return returns direct memory allocator.
   */
  public static MemoryAllocator directAllocator() {
    return new DirectMemoryAllocator();
  }

  /**
   * Get pooled memory allocator.
   *
   * @param poolSize pool size.
   * @param maxPoolSize maximum pool size.
   * @param maxMemoryCapacity memory capacity per buffer.
   * @return returns pooled {@link MemoryAllocator}.
   */
  public static MemoryAllocator allocator(int poolSize, int maxPoolSize, int maxMemoryCapacity) {
    synchronized (Memories.class) {
      return new PooledHeapMemoryAllocator(poolSize, maxPoolSize, maxMemoryCapacity);
    }
  }

  /**
   * Get pooled direct memory allocator.
   *
   * @param poolSize pool size.
   * @param maxPoolSize maximum pool size.
   * @param maxMemoryCapacity memory capacity per buffer.
   * @return returns pooled {@link MemoryAllocator}.
   */
  public static MemoryAllocator directAllocator(
      int poolSize, int maxPoolSize, int maxMemoryCapacity) {
    synchronized (Memories.class) {
      return new PooledDirectMemoryAllocator(poolSize, maxPoolSize, maxMemoryCapacity);
    }
  }

  /** Wrapper */

  /**
   * Wrap direct memory address into {@link Memory} object with bounds checking.
   *
   * @param memoryAddress memory address.
   * @param size size of memory.
   * @return returns {@link Memory}.
   * @throws UnsupportedOperationException maybe unsafe is unavailable.
   */
  @Deprecated
  public static Memory wrap(long memoryAddress, int size) throws UnsupportedOperationException {
    return wrap(memoryAddress, size, true);
  }

  /**
   * Wrap direct memory address into {@link Memory} object.
   *
   * @param memoryAddress memory address.
   * @param size size of memory.
   * @param checking if true it will do bounds checking for every get/set method, false will not
   *     bounds checking.
   * @return returns {@link Memory}.
   * @throws UnsupportedOperationException maybe unsafe is unavailable.
   */
  @Deprecated
  public static Memory wrap(long memoryAddress, int size, boolean checking)
      throws UnsupportedOperationException {
    Validate.notIllegalArgument(size > 0, String.format("size: %d (expected: > 0)", size));
    throw new UnsupportedOperationException();
  }

  /**
   * Wrap direct {@link ByteBuffer} into {@link Memory} with bounds checking.
   *
   * @param buffer direct buffer.
   * @return returns {@link Memory}.
   */
  public static Memory wrap(ByteBuffer buffer) {
    Validate.notIllegalArgument(buffer != null, "buffer: null (expected: non null)");
    Memory memory = new DirectByteBuffer(0, buffer, buffer.capacity(), buffer.capacity(), 0, 0);
    return memory;
  }

  /**
   * Wrap direct {@link ByteBuffer} into {@link Memory}.
   *
   * @param buffer direct buffer.
   * @param checking if true it will do bounds checking for every get/set method, false will not
   *     bounds checking.
   * @return returns {@link Memory}.
   */
  @Deprecated
  public static Memory wrap(ByteBuffer buffer, boolean checking) {
    Validate.notIllegalArgument(buffer != null, "buffer: null (expected: non null)");
    Memory memory = new DirectByteBuffer(0, buffer, buffer.capacity(), buffer.capacity(), 0, 0);
    return memory;
  }

  /**
   * Wrap hex string into {@link Memory}.
   *
   * @param hexStream hex string.
   * @return returns {@link Memory}.
   */
  public static Memory wrap(CharSequence hexStream) {
    Memory memory = wrap(hexStream, true, allocator());
    memory.setIndex(0, memory.capacity());
    return memory;
  }

  /**
   * Wrap hex string into {@link Memory}.
   *
   * @param hexStream hex string.
   * @param checking if true it will do bounds checking for every get/set method, false will not
   *     bounds checking.
   * @param memoryAllocator memory allocator.
   * @return returns {@link Memory}.
   * @throws IllegalArgumentException invalid hex characters.
   */
  public static Memory wrap(
      CharSequence hexStream, boolean checking, MemoryAllocator memoryAllocator) {
    byte[] bytes = Hexs.parseHex(hexStream.toString());
    return wrap(bytes, checking);
  }

  /**
   * Wrap bytes array into {@link Memory}.
   *
   * @param bytes raw bytes.
   * @param checking if true it will do bounds checking for every get/set method, false will not
   *     bounds checking.
   * @return returns {@link Memory}.
   */
  public static Memory wrap(byte[] bytes, boolean checking) {
    Validate.notIllegalArgument(
        bytes != null, String.format("hexStream: null (expected: non null)"));
    Memory memory =
        new DirectByteBuffer(0, ByteBuffer.wrap(bytes), bytes.length, bytes.length, 0, 0);
    return memory;
  }

  /** Assember */

  /**
   * Assemble (combining) memory buffers (copying memories into single buffer).
   *
   * @param memories list of memory.
   * @return returns new direct {@link Memory} instance.
   */
  public static Memory assemble(Memory... memories) {
    int capacity = 0;
    int maxCapacity = 0;
    for (int i = 0; i < memories.length; i++) {
      capacity += memories[i].capacity();
      maxCapacity += memories[i].maxCapacity();
    }
    Memory memory = allocator().allocate(capacity, maxCapacity);
    int index = 0;
    for (int i = 0; i < memories.length; i++) {
      memory.setBytes(index, memories[i], 0, memories[i].capacity());
      index += memories[i].capacity();
    }
    return memory;
  }

  /**
   * Assemble (combining) memory buffers (copying memories into single buffer).
   *
   * @return returns new direct {@link Memory} instance.
   */
  public static Memory assemble(Memory m1, Memory m2) {
    return assemble(new Memory[] {m1, m2});
  }

  /**
   * Assemble (combining) memory buffers (copying memories into single buffer).
   *
   * @return returns new direct {@link Memory} instance.
   */
  public static Memory assemble(Memory m1, Memory m2, Memory m3) {
    return assemble(new Memory[] {m1, m2, m3});
  }

  /**
   * Assemble (combining) memory buffers (copying memories into single buffer).
   *
   * @return returns new direct {@link Memory} instance.
   */
  public static Memory assemble(Memory m1, Memory m2, Memory m3, Memory m4) {
    return assemble(new Memory[] {m1, m2, m3, m4});
  }

  /**
   * Assemble (combining) memory buffers (copying memories into single buffer).
   *
   * @return returns new direct {@link Memory} instance.
   */
  public static Memory assemble(Memory m1, Memory m2, Memory m3, Memory m4, Memory m5) {
    return assemble(new Memory[] {m1, m2, m3, m4, m5});
  }

  /**
   * Assemble (combining) memory buffers (copying memories into single buffer).
   *
   * @return returns new direct {@link Memory} instance.
   */
  public static Memory assemble(Memory m1, Memory m2, Memory m3, Memory m4, Memory m5, Memory m6) {
    return assemble(new Memory[] {m1, m2, m3, m4, m5, m6});
  }

  /**
   * Assemble (combining) memory buffers (copying memories into single buffer).
   *
   * @return returns new direct {@link Memory} instance.
   */
  public static Memory assemble(
      Memory m1, Memory m2, Memory m3, Memory m4, Memory m5, Memory m6, Memory m7) {
    return assemble(new Memory[] {m1, m2, m3, m4, m5, m6, m7});
  }
}
