/** This code is licenced under the GPL version 2. */
package pcap.common.memory;

import pcap.common.annotation.Inclubating;
import pcap.common.internal.ByteBufferHelper;
import pcap.common.internal.Unsafe;
import pcap.common.util.Hexs;
import pcap.common.util.Validate;

import java.nio.ByteBuffer;
import java.util.Map;
import java.util.Queue;
import java.util.concurrent.ConcurrentHashMap;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
@Inclubating
public final class Memories {

  static Map<Integer, Queue<PooledMemory>> POOLS;

  /**
   * Get default memory allocator.
   *
   * @return returns default memory allocator.
   */
  public static MemoryAllocator allocator() {
    return new DefaultMemoryAllocator();
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
   * Get heap memory allocator.
   *
   * @return returns heap memory allocator.
   */
  public static MemoryAllocator heapAllocator() {
    return new HeapMemoryAllocator();
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
      if (POOLS == null) {
        POOLS = new ConcurrentHashMap<Integer, Queue<PooledMemory>>();
      }
      return new PooledMemoryAllocator(poolSize, maxPoolSize, maxMemoryCapacity);
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
      if (POOLS == null) {
        POOLS = new ConcurrentHashMap<Integer, Queue<PooledMemory>>();
      }
      return new PooledDirectMemoryAllocator(poolSize, maxPoolSize, maxMemoryCapacity);
    }
  }

  /**
   * Get pooled heap memory allocator.
   *
   * @param poolSize pool size.
   * @param maxPoolSize maximum pool size.
   * @param maxMemoryCapacity memory capacity per buffer.
   * @return returns pooled {@link MemoryAllocator}.
   */
  public static MemoryAllocator heapAllocator(
      int poolSize, int maxPoolSize, int maxMemoryCapacity) {
    synchronized (Memories.class) {
      if (POOLS == null) {
        POOLS = new ConcurrentHashMap<Integer, Queue<PooledMemory>>();
      }
      return new PooledHeapMemoryAllocator(poolSize, maxPoolSize, maxMemoryCapacity);
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
  public static Memory wrap(long memoryAddress, int size, boolean checking)
      throws UnsupportedOperationException {
    Validate.notIllegalArgument(size > 0, String.format("size: %d (expected: > 0)", size));
    if (MemoryAllocator.UNSAFE_BUFFER) {
      Memory memory;
      if (checking) {
        memory = new CheckedMemory(memoryAddress, size, size);
      } else {
        memory = new UncheckedMemory(memoryAddress, size, size);
      }
      memory.writerIndex(memory.capacity());
      return memory;
    } else {
      throw new UnsupportedOperationException();
    }
  }

  /**
   * Wrap direct {@link ByteBuffer} into {@link Memory} with bounds checking.
   *
   * @param buffer direct buffer.
   * @return returns {@link Memory}.
   */
  public static Memory wrap(ByteBuffer buffer) {
    return wrap(buffer, true);
  }

  /**
   * Wrap direct {@link ByteBuffer} into {@link Memory}.
   *
   * @param buffer direct buffer.
   * @param checking if true it will do bounds checking for every get/set method, false will not
   *     bounds checking.
   * @return returns {@link Memory}.
   */
  public static Memory wrap(ByteBuffer buffer, boolean checking) {
    Validate.notIllegalArgument(buffer != null, "buffer: null (expected: non null)");
    Memory memory;
    if (MemoryAllocator.UNSAFE_BUFFER) {
      int capacity = buffer.capacity();
      long address = ByteBufferHelper.directByteBufferAddress(buffer);
      if (checking) {
        memory = new CheckedMemory(buffer, address, capacity, capacity, 0, 0);
      }
      memory = new UncheckedMemory(buffer, address, capacity, capacity, 0, 0);
    } else {
      memory = new ByteBuf(0, buffer, buffer.capacity(), buffer.capacity(), 0, 0);
    }
    return memory;
  }

  /**
   * Wrap hex string into {@link Memory}.
   *
   * @param hexStream hex string.
   * @return returns {@link Memory}.
   */
  public static Memory wrap(CharSequence hexStream) {
    Memory memory = wrap(hexStream, true, new DefaultMemoryAllocator());
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
    if (memoryAllocator instanceof DirectMemoryAllocator
        || memoryAllocator instanceof PooledDirectMemoryAllocator) {
      Memory memory = memoryAllocator.allocate(bytes.length, checking);
      memory.setBytes(0, bytes);
      return memory;
    } else {
      return wrap(bytes, checking);
    }
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
    Memory memory;
    if (Unsafe.HAS_UNSAFE) {
      if (checking) {
        memory = new CheckedByteArray(0, bytes, bytes.length, bytes.length, 0, 0);
      } else {
        memory = new UncheckedByteArray(0, bytes, bytes.length, bytes.length, 0, 0);
      }
    } else {
      memory = new ByteBuf(0, ByteBuffer.wrap(bytes), bytes.length, bytes.length, 0, 0);
    }
    return memory;
  }

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

  static void offer(Memory memory) {
    //    if (memory instanceof Pooled) {
    POOLS.get(memory.maxCapacity()).offer(new PooledMemory(memory));
    //    }
  }

  static Memory poll(int maxCapacity) {
    PooledMemory pooledMemory = POOLS.get(maxCapacity).poll();
    if (pooledMemory != null) {
      Memory memory = pooledMemory.get();
      //      if (memory instanceof Pooled) {
      return memory;
      //      }
    }
    return null;
  }
}
