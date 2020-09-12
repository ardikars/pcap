package pcap.common.memory;

import java.nio.ByteBuffer;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.runner.RunWith;

@RunWith(JUnitPlatform.class)
public class MemoryAllocatorTest {

  @Test
  public void noMemoryAllocatorTest() {
    Assertions.assertThrows(
        IllegalArgumentException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            MemoryAllocator.Creator.create("NoMemoryAllocator");
          }
        });
    Assertions.assertThrows(
        IllegalArgumentException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            MemoryAllocator.Creator.create("NoMemoryAllocator", 10, 50, 1024);
          }
        });
  }

  @Test
  public void nioDirectMemoryAllocatorTest() {
    final byte[] value = new byte[] {0, 1, 2, 4};
    final MemoryAllocator allocator = MemoryAllocator.Creator.create("NioDirectMemoryAllocator");
    final MemoryAllocator pooladAllocator =
        MemoryAllocator.Creator.create("NioPooledDirectMemoryAllocator", 5, 10, 8);

    Assertions.assertThrows(
        IllegalArgumentException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            MemoryAllocator.Creator.create("NioDirectMemoryAllocator", 5, 10, 8);
          }
        });
    Assertions.assertThrows(
        IllegalArgumentException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            MemoryAllocator.Creator.create("NioPooledDirectMemoryAllocator");
          }
        });

    Assertions.assertThrows(
        IllegalArgumentException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            pooladAllocator.allocate(-1, 1, 0, 0);
          }
        });
    Assertions.assertThrows(
        IllegalArgumentException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            pooladAllocator.allocate(1, -1, 0, 0);
          }
        });
    Assertions.assertThrows(
        IllegalArgumentException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            pooladAllocator.allocate(2, 1, 0, 0);
          }
        });
    Assertions.assertThrows(
        IllegalArgumentException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            pooladAllocator.allocate(2, 1, 0, 0);
          }
        });
    Assertions.assertThrows(
        IllegalArgumentException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            pooladAllocator.allocate(1024, 1, 0, 0);
          }
        });
    Assertions.assertThrows(
        IllegalArgumentException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            pooladAllocator.allocate(1, 1024, 0, 0);
          }
        });
    Assertions.assertThrows(
        IllegalArgumentException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            pooladAllocator.allocate(1, 1, -1, 0);
          }
        });
    Assertions.assertThrows(
        IllegalArgumentException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            pooladAllocator.allocate(1, 1, 0, -1);
          }
        });

    final Memory buf = allocator.wrap(value);
    Assertions.assertNotNull(buf);

    final Memory pooledBuf = pooladAllocator.wrap(value);
    Assertions.assertNotNull(pooledBuf);

    final ByteBuffer direct = ByteBuffer.allocateDirect(value.length);
    direct.put(value);
    direct.clear();
    final Memory directBuf = allocator.wrap(direct);
    Assertions.assertNotNull(direct);

    direct.clear();
    final Memory pooledDirectBuf = pooladAllocator.wrap(direct);
    Assertions.assertNotNull(pooledDirectBuf);

    Assertions.assertThrows(
        IllegalArgumentException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            allocator.assemble();
          }
        });
    Assertions.assertThrows(
        IllegalArgumentException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            pooladAllocator.assemble();
          }
        });
    Assertions.assertThrows(
        IllegalArgumentException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            allocator.assemble(null);
          }
        });
    Assertions.assertThrows(
        IllegalArgumentException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            pooladAllocator.assemble(null);
          }
        });
    Assertions.assertThrows(
        IllegalArgumentException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            allocator.assemble(buf);
          }
        });
    Assertions.assertThrows(
        IllegalArgumentException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            pooladAllocator.assemble(pooledBuf);
          }
        });
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
    final MemoryAllocator pooladAllocator =
        MemoryAllocator.Creator.create("NioPooledDirectMemoryAllocator", 1, 2, 4);
    final MemoryAllocator pooladAllocator2 =
        MemoryAllocator.Creator.create("NioPooledDirectMemoryAllocator", 1, 2, 4);

    final Memory first = pooladAllocator.allocate(4);
    final Memory first2 = pooladAllocator2.allocate(4);

    first.release();
    Assertions.assertThrows(
        IllegalStateException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            ((AbstractMemoryAllocator.AbstractPooledMemoryAllocator) pooladAllocator)
                .offer((Memory.Pooled) first);
          }
        });
    Assertions.assertThrows(
        IllegalStateException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            ((Memory.Pooled) first).retain();
          }
        });

    final Memory second = pooladAllocator.allocate(4);
    final Memory third = pooladAllocator.allocate(4);

    Assertions.assertThrows(
        IllegalStateException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            pooladAllocator.allocate(4);
          }
        });
    second.release();
    third.release();
    Assertions.assertThrows(
        IllegalStateException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            ((AbstractMemoryAllocator.AbstractPooledMemoryAllocator) pooladAllocator)
                .offer((Memory.Pooled) first2);
          }
        });
    Assertions.assertThrows(
        IllegalStateException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            ((AbstractMemoryAllocator.AbstractPooledMemoryAllocator) pooladAllocator)
                .retainBuffer(
                    (Memory.Pooled) first2,
                    first2.capacity(),
                    first2.writerIndex(),
                    first2.readerIndex());
          }
        });
  }
}
