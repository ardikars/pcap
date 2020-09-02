package pcap.common.memory;

import java.nio.ByteBuffer;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.runner.RunWith;

@RunWith(JUnitPlatform.class)
public class MemoryAllocatorTest {

  @Test
  public void noMemoryAllocatorTest() {
    Assertions.assertThrows(
        IllegalArgumentException.class, () -> MemoryAllocator.create("NoMemoryAllocator"));
    Assertions.assertThrows(
        IllegalArgumentException.class,
        () -> MemoryAllocator.create("NoMemoryAllocator", 10, 50, 1024));
  }

  @Test
  public void nioDirectMemoryAllocatorTest() {
    byte[] value = new byte[] {0, 1, 2, 4};
    MemoryAllocator allocator = MemoryAllocator.create("NioDirectMemoryAllocator");
    MemoryAllocator pooladAllocator =
        MemoryAllocator.create("NioPooledDirectMemoryAllocator", 5, 10, 8);

    Assertions.assertThrows(
        IllegalArgumentException.class,
        () -> MemoryAllocator.create("NioDirectMemoryAllocator", 5, 10, 8));
    Assertions.assertThrows(
        IllegalArgumentException.class,
        () -> MemoryAllocator.create("NioPooledDirectMemoryAllocator"));

    Assertions.assertThrows(
        IllegalArgumentException.class, () -> pooladAllocator.allocate(-1, 1, 0, 0));
    Assertions.assertThrows(
        IllegalArgumentException.class, () -> pooladAllocator.allocate(1, -1, 0, 0));
    Assertions.assertThrows(
        IllegalArgumentException.class, () -> pooladAllocator.allocate(2, 1, 0, 0));
    Assertions.assertThrows(
        IllegalArgumentException.class, () -> pooladAllocator.allocate(2, 1, 0, 0));
    Assertions.assertThrows(
        IllegalArgumentException.class, () -> pooladAllocator.allocate(1024, 1, 0, 0));
    Assertions.assertThrows(
        IllegalArgumentException.class, () -> pooladAllocator.allocate(1, 1024, 0, 0));
    Assertions.assertThrows(
        IllegalArgumentException.class, () -> pooladAllocator.allocate(1, 1, -1, 0));
    Assertions.assertThrows(
        IllegalArgumentException.class, () -> pooladAllocator.allocate(1, 1, 0, -1));

    Memory buf = allocator.wrap(value);
    Assertions.assertNotNull(buf);

    Memory pooledBuf = pooladAllocator.wrap(value);
    Assertions.assertNotNull(pooledBuf);

    ByteBuffer direct = ByteBuffer.allocateDirect(value.length);
    direct.put(value);
    direct.clear();
    Memory directBuf = allocator.wrap(direct);
    Assertions.assertNotNull(direct);

    direct.clear();
    Memory pooledDirectBuf = pooladAllocator.wrap(direct);
    Assertions.assertNotNull(pooledDirectBuf);

    Assertions.assertThrows(IllegalArgumentException.class, () -> allocator.assemble());
    Assertions.assertThrows(IllegalArgumentException.class, () -> pooladAllocator.assemble());
    Assertions.assertThrows(IllegalArgumentException.class, () -> allocator.assemble(null));
    Assertions.assertThrows(IllegalArgumentException.class, () -> pooladAllocator.assemble(null));
    Assertions.assertThrows(IllegalArgumentException.class, () -> allocator.assemble(buf));
    Assertions.assertThrows(
        IllegalArgumentException.class, () -> pooladAllocator.assemble(pooledBuf));
    Memory assemble = allocator.assemble(buf, directBuf);
    Assertions.assertNotNull(assemble);
    Memory pooledAssemble = pooladAllocator.assemble(pooledBuf, pooledDirectBuf);
    Assertions.assertNotNull(pooledAssemble);
    buf.release();
    directBuf.release();
    pooledAssemble.release();
    pooledBuf.release();
    pooledDirectBuf.release();
    assemble.release();
  }

  @Test
  public void nioPooledDirectMemoryAllocatorTest() {
    MemoryAllocator pooladAllocator =
        MemoryAllocator.create("NioPooledDirectMemoryAllocator", 1, 2, 4);
    MemoryAllocator pooladAllocator2 =
        MemoryAllocator.create("NioPooledDirectMemoryAllocator", 1, 2, 4);

    Memory first = pooladAllocator.allocate(4);
    Memory first2 = pooladAllocator2.allocate(4);

    first.release();
    Assertions.assertThrows(
        IllegalStateException.class,
        () ->
            ((AbstractMemoryAllocator.AbstractPooledMemoryAllocator) pooladAllocator)
                .offer((Memory.Pooled) first));
    Assertions.assertThrows(IllegalStateException.class, () -> ((Memory.Pooled) first).retain());

    Memory second = pooladAllocator.allocate(4);
    Memory third = pooladAllocator.allocate(4);

    Assertions.assertThrows(IllegalStateException.class, () -> pooladAllocator.allocate(4));
    second.release();
    third.release();
    Assertions.assertThrows(
        IllegalStateException.class,
        () ->
            ((AbstractMemoryAllocator.AbstractPooledMemoryAllocator) pooladAllocator)
                .offer((Memory.Pooled) first2));
    Assertions.assertThrows(
        IllegalStateException.class,
        () ->
            ((AbstractMemoryAllocator.AbstractPooledMemoryAllocator) pooladAllocator)
                .retainBuffer(
                    (Memory.Pooled) first2,
                    first2.capacity(),
                    first2.writerIndex(),
                    first2.readerIndex()));
  }
}
