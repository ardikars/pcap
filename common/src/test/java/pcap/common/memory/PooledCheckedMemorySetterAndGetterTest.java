/** This code is licenced under the GPL version 2. */
package pcap.common.memory;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.runner.RunWith;

@RunWith(JUnitPlatform.class)
public class PooledCheckedMemorySetterAndGetterTest extends AbstractMemorySetterAndGetterTest {

  private final MemoryAllocator MEMORY_ALLOCATOR =
      Memories.allocator(2, 5, DEFAULT_CAPACITY + INT_SIZE);

  public PooledCheckedMemorySetterAndGetterTest() {
    super(true);
  }

  @Override
  protected MemoryAllocator memoryAllocator() {
    return MEMORY_ALLOCATOR;
  }

  @BeforeEach
  public void allocate() {
    memory = memoryAllocator().allocate(DEFAULT_CAPACITY, DEFAULT_CAPACITY + INT_SIZE, true);
  }

  @AfterEach
  public void deallocate() {
    memory.release();
    MEMORY_ALLOCATOR.close();
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
  public void shotLETest() {
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
  public void setBytesTest() {
    doSetBytesTest();
  }

  @Test
  @Override
  public void getBytesTest() {
    doGetBytesTest();
  }
}
