package pcap.common.memory;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.runner.RunWith;

@RunWith(JUnitPlatform.class)
public class ByteBufTest extends AbstractMemoryTest {

  private final MemoryAllocator MEMORY_ALLOCATOR = new HeapMemoryAllocator();

  @Override
  protected MemoryAllocator memoryAllocator() {
    return MEMORY_ALLOCATOR;
  }

  @BeforeEach
  @Override
  public void allocate() {
    memory = memoryAllocator().allocate(DEFAULT_CAPACITY, DEFAULT_CAPACITY + INT_SIZE, true);
    Memory mem = new CheckedMemory(memory.memoryAddress(), memory.capacity(), memory.maxCapacity());
    assert mem.memoryAddress() == memory.memoryAddress();
  }

  @AfterEach
  @Override
  public void deallocate() {
    memory.release();
  }

  @Test
  @Override
  public void capacityAndMaxCapacityTest() {
    doCapacityAndMaxCapacityTest();
  }

  @Test
  @Override
  public void readerAndWriterIndexTest() {
    doReaderAndWriterIndexTest();
  }

  @Override
  public void isReadableTest() {
    doIsReadableTest();
  }

  @Test
  @Override
  public void readableWriteableAndMaxWriableBytesTest() {
    doReadableWriteableAndMaxWriableBytesTest();
  }

  @Test
  @Override
  public void readerIndexTest() {
    doReaderIndexTest();
  }

  @Test
  @Override
  public void writerIndexTest() {
    doWriterIndexTest();
  }

  @Test
  @Override
  public void skipBytesTest() {
    doSkipBytesTest();
  }

  @Test
  @Override
  public void copyTest() {
    doSliceTest();
  }

  @Test
  @Override
  public void sliceTest() {
    doCopyTest();
  }

  @Test
  @Override
  public void clearTest() {
    doClearTest();
  }

  @Test
  @Override
  public void newCapacityTest() {
    // doNewCapacityTest();
  }

  @Test
  @Override
  public void duplicateTest() {
    // doDuplicateTest();
  }

  @Test
  @Override
  public void nioBufferTest() {
    // doNioBufferTest();
  }
}