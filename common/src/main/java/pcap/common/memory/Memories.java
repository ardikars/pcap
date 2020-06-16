/** This code is licenced under the GPL version 2. */
package pcap.common.memory;

import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.Random;
import pcap.common.annotation.Inclubating;
import pcap.common.memory.internal.allocator.DirectMemoryAllocator;
import pcap.common.memory.internal.allocator.HeapMemoryAllocator;
import pcap.common.memory.internal.allocator.PooledDirectMemoryAllocator;
import pcap.common.memory.internal.allocator.PooledHeapMemoryAllocator;
import pcap.common.memory.internal.nio.DirectByteBuffer;
import pcap.common.memory.internal.nio.HeapByteBuffer;
import pcap.common.util.Hexs;
import pcap.common.util.Validate;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
@Inclubating
public final class Memories {

  private Memories() {
    //
  }

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
   * Wrap direct {@link ByteBuffer} into {@link Memory} with bounds checking.
   *
   * @param buffer direct buffer.
   * @return returns {@link Memory}.
   */
  public static Memory wrap(ByteBuffer buffer) {
    Validate.notIllegalArgument(buffer != null, "buffer: null (expected: non null)");
    if (buffer.isDirect()) {
      return new DirectByteBuffer(0, buffer, buffer.capacity(), buffer.capacity(), 0, 0);
    } else {
      return new HeapByteBuffer(0, buffer, buffer.capacity(), buffer.capacity(), 0, 0);
    }
  }

  /**
   * Wrap hex string into {@link Memory}.
   *
   * @param hexStream hex string.
   * @return returns {@link Memory}.
   */
  public static Memory wrap(CharSequence hexStream) {
    return wrap(hexStream, allocator());
  }

  /**
   * Wrap hex string into {@link Memory}.
   *
   * @param hexStream hex string.
   * @param memoryAllocator memory allocator.
   * @return returns {@link Memory}.
   * @throws IllegalArgumentException invalid hex characters.
   */
  public static Memory wrap(CharSequence hexStream, MemoryAllocator memoryAllocator) {
    byte[] bytes = Hexs.parseHex(hexStream.toString());
    return wrap(bytes, memoryAllocator);
  }

  /**
   * Wrap bytes array into {@link Memory}.
   *
   * @param bytes raw bytes.
   * @return returns {@link Memory}.
   */
  public static Memory wrap(byte[] bytes) {
    return wrap(bytes, allocator());
  }

  /**
   * Wrap bytes array into {@link Memory}.
   *
   * @param bytes raw bytes.
   * @param memoryAllocator memory allocator.
   * @return returns {@link Memory}.
   */
  public static Memory wrap(byte[] bytes, MemoryAllocator memoryAllocator) {
    Validate.notIllegalArgument(bytes != null, "hexStream: null (expected: non null)");
    Memory memory = memoryAllocator.allocate(bytes.length);
    memory.writeBytes(bytes);
    return memory;
  }

  /**
   * Allocate buffer and initialize with random values.
   *
   * @param capacity size of buffer.
   * @return returns {@link Memory} with random values.
   */
  public static Memory allocateRandom(int capacity) {
    return allocateRandom(capacity, allocator());
  }

  /**
   * Allocate buffer and initialize with random values.
   *
   * @param capacity size of buffer.
   * @param allocator memory allocator.
   * @return returns {@link Memory} with random values.
   */
  public static Memory allocateRandom(int capacity, MemoryAllocator allocator) {
    return allocateRandom(capacity, allocator, new SecureRandom());
  }

  /**
   * Allocate buffer and initialize with random values.
   *
   * @param capacity size of buffer.
   * @param allocator memory allocator.
   * @param random random.
   * @return returns {@link Memory} with random values.
   */
  public static Memory allocateRandom(int capacity, MemoryAllocator allocator, Random random) {
    Memory memory = allocator.allocate(capacity);
    while (memory.writableBytes() >= 4) {
      memory.writeInt(random.nextInt());
    }
    while (memory.writableBytes() > 0) {
      memory.writeByte(random.nextInt());
    }
    return memory;
  }

  /** Assember */

  /**
   * Assemble (combining) memory buffers (copying memories into single buffer).
   *
   * @param memories list of memory.
   * @return returns new direct {@link Memory} instance.
   */
  private static Memory doAssemble(Memory... memories) {
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
  public static Memory assemble(Memory[] memories) {
    return doAssemble(memories);
  }

  /**
   * Assemble (combining) memory buffers (copying memories into single buffer).
   *
   * @return returns new direct {@link Memory} instance.
   */
  public static Memory assemble(Memory m1, Memory m2) {
    return doAssemble(m1, m2);
  }

  /**
   * Assemble (combining) memory buffers (copying memories into single buffer).
   *
   * @return returns new direct {@link Memory} instance.
   */
  public static Memory assemble(Memory m1, Memory m2, Memory m3) {
    return doAssemble(m1, m2, m3);
  }

  /**
   * Assemble (combining) memory buffers (copying memories into single buffer).
   *
   * @return returns new direct {@link Memory} instance.
   */
  public static Memory assemble(Memory m1, Memory m2, Memory m3, Memory m4) {
    return doAssemble(m1, m2, m3, m4);
  }

  /**
   * Assemble (combining) memory buffers (copying memories into single buffer).
   *
   * @return returns new direct {@link Memory} instance.
   */
  public static Memory assemble(Memory m1, Memory m2, Memory m3, Memory m4, Memory m5) {
    return assemble(m1, m2, m3, m4, m5);
  }

  /**
   * Assemble (combining) memory buffers (copying memories into single buffer).
   *
   * @return returns new direct {@link Memory} instance.
   */
  public static Memory assemble(Memory m1, Memory m2, Memory m3, Memory m4, Memory m5, Memory m6) {
    return doAssemble(m1, m2, m3, m4, m5, m6);
  }

  /**
   * Assemble (combining) memory buffers (copying memories into single buffer).
   *
   * @return returns new direct {@link Memory} instance.
   */
  public static Memory assemble(
      Memory m1, Memory m2, Memory m3, Memory m4, Memory m5, Memory m6, Memory m7) {
    return doAssemble(m1, m2, m3, m4, m5, m6, m7);
  }
}
