/** This code is licenced under the GPL version 2. */
package pcap.common.memory;

import java.nio.ByteBuffer;
import java.util.Iterator;
import java.util.ServiceLoader;
import pcap.common.annotation.Inclubating;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
@Inclubating
public interface MemoryAllocator {

  class Creator {

    public static MemoryAllocator create(String name) {
      ServiceLoader<MemoryAllocator> loader = ServiceLoader.load(MemoryAllocator.class);
      Iterator<MemoryAllocator> iterator = loader.iterator();
      while (iterator.hasNext()) {
        MemoryAllocator service = iterator.next();
        if (service.name().equals(name)
            && !(service instanceof AbstractMemoryAllocator.AbstractPooledMemoryAllocator)) {
          return service;
        }
      }
      throw new IllegalArgumentException("No memory allocator implementation for (" + name + ").");
    }

    public static MemoryAllocator create(
        String name, int poolSize, int maxPoolSize, long maxCapacity) {
      ServiceLoader<MemoryAllocator> loader = ServiceLoader.load(MemoryAllocator.class);
      Iterator<MemoryAllocator> iterator = loader.iterator();
      while (iterator.hasNext()) {
        MemoryAllocator service = iterator.next();
        if (service.name().equals(name)
            && service instanceof AbstractMemoryAllocator.AbstractPooledMemoryAllocator) {
          ((AbstractMemoryAllocator.AbstractPooledMemoryAllocator) service)
              .create(poolSize, maxPoolSize, maxCapacity);
          return service;
        }
      }
      throw new IllegalArgumentException("No memory allocator implementation for (" + name + ").");
    }
  }

  String name();

  Memory allocate(long capacity);

  Memory allocate(long capacity, long maxCapacity);

  Memory allocate(long capacity, long maxCapacity, long readerIndex, long writerIndex);

  Memory wrap(byte[] bytes);

  Memory wrap(ByteBuffer bb);

  Memory assemble(Memory... memories);
}
