package pcap.common.memory.nio;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.runner.RunWith;
import pcap.common.memory.AbstractMemoryWriterAndReaderTest;
import pcap.common.memory.MemoryAllocator;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
@RunWith(JUnitPlatform.class)
public class HeapByteBufferWriterAndReaderTest extends AbstractMemoryWriterAndReaderTest {

  private final MemoryAllocator MEMORY_ALLOCATOR =
      MemoryAllocator.Creator.create("NioHeapMemoryAllocator");

  @Override
  protected MemoryAllocator memoryAllocator() {
    return MEMORY_ALLOCATOR;
  }

  @BeforeEach
  @Override
  public void allocate() {
    memory = memoryAllocator().allocate(DEFAULT_CAPACITY, DEFAULT_CAPACITY + INT_SIZE);
  }

  @AfterEach
  @Override
  public void deallocate() {
    memory.release();
  }

  @Test
  @Override
  public void booleanTest() {
    doBooleanTest();
  }

  @Test
  @Override
  public void byteTest() {
    doByteTest();
  }

  @Test
  @Override
  public void unsignedByteTest() {
    doUnsignedByteTest();
  }

  @Test
  @Override
  public void shortTest() {
    doShortTest();
  }

  @Test
  @Override
  public void shortLETest() {
    doShortLETest();
  }

  @Test
  @Override
  public void unsignedShortTest() {
    doUnsignedShortTest();
  }

  @Test
  @Override
  public void unsignedShortLETest() {
    doUnsignedShortLETest();
  }

  @Test
  @Override
  public void intTest() {
    doIntTest();
  }

  @Test
  @Override
  public void intLETest() {
    doIntLETest();
  }

  @Test
  @Override
  public void unsignedIntTest() {
    doUnsignedIntTest();
  }

  @Test
  @Override
  public void unsignedIntLETest() {
    doUnsignedIntLETest();
  }

  @Test
  @Override
  public void floatTest() {
    doFloatTest();
  }

  @Test
  @Override
  public void floatLETest() {
    doFloatLETest();
  }

  @Test
  @Override
  public void longTest() {
    doLongTest();
  }

  @Test
  @Override
  public void longLETest() {
    doLongLETest();
  }

  @Test
  @Override
  public void doubleTest() {
    doDoubleTest();
  }

  @Test
  @Override
  public void doubleLETest() {
    doDoubleLETest();
  }

  @Test
  @Override
  public void writeBytesTest() {
    doWriteBytesTest();
  }

  @Test
  @Override
  public void readBytesTest() {
    doReadBytesTest();
  }

  @Test
  @Override
  public void writeReadCharSequaceTest() {
    doWriteReadCharSequaceTest();
  }
}
