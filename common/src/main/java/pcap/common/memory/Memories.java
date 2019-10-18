/** This code is licenced under the GPL version 2. */
package pcap.common.memory;

import java.nio.ByteBuffer;
import java.util.Map;
import java.util.Queue;
import java.util.concurrent.ConcurrentHashMap;
import pcap.common.annotation.Inclubating;
import pcap.common.internal.ByteBufferHelper;
import pcap.common.internal.Unsafe;
import pcap.common.util.Hexs;
import pcap.common.util.Validate;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
@Inclubating
public final class Memories {

  private static MemoryAllocator DEFAULT_MEMORY_ALLOCATOR = new DefaultMemoryAllocator();

  static Map<Integer, Queue<PooledMemory>> POOLS;

  public static MemoryAllocator allocator() {
    return DEFAULT_MEMORY_ALLOCATOR;
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
   * Wrap direct memory address into {@link Memory} object with bounds checking.
   *
   * @param memoryAddress memory address.
   * @param size size of memory.
   * @return returns {@link Memory}.
   */
  public static Memory wrap(long memoryAddress, int size) {
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
   */
  public static Memory wrap(long memoryAddress, int size, boolean checking) {
    Validate.notIllegalArgument(
        size > 0, new IllegalArgumentException(String.format("size: %d (expected: > 0)", size)));
    if (Unsafe.HAS_UNSAFE && MemoryAllocator.UNSAFE_BUFFER) {
      if (checking) {
        return new CheckedMemory(memoryAddress, size, size);
      } else {
        return new UncheckedMemory(memoryAddress, size, size);
      }
    } else {
      ByteBuffer bbNoCleaner = ByteBufferHelper.wrapDirectByteBuffer(memoryAddress, size);
      return new ByteBuf(0, bbNoCleaner, size, size, 0, 0);
    }
  }

  /**
   * Wrap direct {@link ByteBuffer} into {@link Memory} with bounds checking.
   *
   * @param buffer direct buffer.
   * @return returns {@link Memory}.
   * @throws UnsupportedOperationException is't not direct buffer.
   */
  public static Memory wrap(ByteBuffer buffer) throws UnsupportedOperationException {
    return wrap(buffer, true);
  }

  /**
   * Wrap direct {@link ByteBuffer} into {@link Memory}.
   *
   * @param buffer direct buffer.
   * @param checking if true it will do bounds checking for every get/set method, false will not
   *     bounds checking.
   * @return returns {@link Memory}.
   * @throws UnsupportedOperationException is't not direct buffer.
   */
  public static Memory wrap(ByteBuffer buffer, boolean checking)
      throws UnsupportedOperationException {
    Validate.notIllegalArgument(
        buffer != null, new IllegalArgumentException("buffer: null (expected: non null)"));
    Validate.notIllegalArgument(
        buffer.isDirect(),
        new IllegalArgumentException(
            String.format("buffer.isDirect(): %b (expected: direct buffer)", buffer.isDirect())));
    if (Unsafe.HAS_UNSAFE && MemoryAllocator.UNSAFE_BUFFER) {
      int capacity = buffer.capacity();
      long address = ByteBufferHelper.directByteBufferAddress(buffer);
      if (checking) {
        return new CheckedMemory(buffer, address, capacity, capacity, 0, 0);
      }
      return new UncheckedMemory(buffer, address, capacity, capacity, 0, 0);
    } else {
      return new ByteBuf(0, buffer, buffer.capacity(), buffer.capacity(), 0, 0);
    }
  }

  /**
   * Wrap hex string into {@link Memory}.
   *
   * @param hexStream hex string.
   * @return returns {@link Memory}.
   */
  public static Memory wrap(CharSequence hexStream) {
    return wrap(hexStream, true);
  }

  /**
   * Wrap hex string into {@link Memory}.
   *
   * @param hexStream hex string.
   * @param checking if true it will do bounds checking for every get/set method, false will not
   *     bounds checking.
   * @return returns {@link Memory}.
   * @throws IllegalArgumentException invalid hex characters.
   */
  public static Memory wrap(CharSequence hexStream, boolean checking) {
    return wrap(DEFAULT_MEMORY_ALLOCATOR, hexStream, checking);
  }

  /**
   * Wrap hex string into {@link Memory}.
   *
   * @param allocator memory allocator.
   * @param hexStream hex string.
   * @param checking if true it will do bounds checking for every get/set method, false will not
   *     bounds checking.
   * @return returns {@link Memory}.
   * @throws IllegalArgumentException invalid hex characters.
   */
  public static Memory wrap(MemoryAllocator allocator, CharSequence hexStream, boolean checking) {
    Validate.notIllegalArgument(
        hexStream != null,
        new IllegalArgumentException(String.format("hexStream: null (expected: non null)")));
    byte[] data = Hexs.parseHex(hexStream.toString());
    Memory memory = allocator.allocate(data.length, checking);
    memory.setBytes(0, data);
    return memory;
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
    return wrap(DEFAULT_MEMORY_ALLOCATOR, bytes, checking);
  }

  /**
   * Wrap bytes array into {@link Memory}.
   *
   * @param allocator memory allocator.
   * @param bytes raw bytes.
   * @param checking if true it will do bounds checking for every get/set method, false will not
   *     bounds checking.
   * @return returns {@link Memory}.
   */
  public static Memory wrap(MemoryAllocator allocator, byte[] bytes, boolean checking) {
    Validate.notIllegalArgument(
        bytes != null,
        new IllegalArgumentException(String.format("hexStream: null (expected: non null)")));
    Memory memory = allocator.allocate(bytes.length, checking);
    memory.setBytes(0, bytes);
    return memory;
  }

  /**
   * Wrap bytes array into {@link Memory}.
   *
   * @param bytes raw bytes.
   * @param checking if true it will do bounds checking for every get/set method, false will not
   *     bounds checking.
   * @return returns {@link Memory}.
   */
  public static Memory wrapBytes(byte[] bytes, boolean checking) {
    Validate.notIllegalArgument(
        bytes != null,
        new IllegalArgumentException(String.format("hexStream: null (expected: non null)")));
    if (Unsafe.HAS_UNSAFE) {
      if (checking) {
        return new CheckedByteArray(0, bytes, bytes.length, bytes.length, 0, 0);
      } else {
        return new UncheckedByteArray(0, bytes, bytes.length, bytes.length, 0, 0);
      }
    } else {
      return new ByteBuf(0, ByteBuffer.wrap(bytes), bytes.length, bytes.length, 0, 0);
    }
  }

  static void offer(Memory memory) {
    if (memory instanceof Pooled) {
      POOLS.get(memory.maxCapacity()).offer(new PooledMemory(memory));
    }
  }

  static Memory poll(int maxCapacity) {
    PooledMemory pooledMemory = POOLS.get(maxCapacity).poll();
    if (pooledMemory != null) {
      Memory memory = pooledMemory.get();
      if (memory instanceof Pooled) {
        return memory;
      }
      return null;
    }
    return null;
  }
}
