/** This code is licenced under the GPL version 2. */
package pcap.codec.ip;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.runner.RunWith;
import pcap.codec.BaseTest;
import pcap.codec.TransportLayer;
import pcap.codec.ethernet.Ethernet;
import pcap.codec.ip.ip6.HopByHopOptions;
import pcap.common.memory.Memory;
import pcap.common.memory.internal.nio.PooledDirectByteBuffer;
import pcap.common.util.Hexs;

/** @author <a href="mailto:contact@ardikars.com">Langkuy</a> */
@RunWith(JUnitPlatform.class)
public class Ip6HopByHopOptionTest extends BaseTest {

  private byte[] data = Hexs.parseHex(IPV6_HOP_BY_HOP_OPTION);

  private Memory buf = allocator.allocate(data.length);

  @Override
  public void before() {
    buf.writeBytes(data);
    ethernet = Ethernet.newPacket(buf);
    final HopByHopOptions first = ethernet.getFirst(HopByHopOptions.class);
    Memory memory = first.buffer();
    Assertions.assertEquals(0, memory.readerIndex());
    Assertions.assertEquals(first.header().length(), memory.writerIndex());
  }

  private HopByHopOptions build() {
    HopByHopOptions.Builder builder = new HopByHopOptions.Builder();
    return builder
        .nextHeader(TransportLayer.IPV6)
        .extensionLength(0)
        .options(new byte[] {1, 2, 3, 4, 5, 6})
        .build();
  }

  @Test
  public void buildTest() {
    final HopByHopOptions hopByHopOptions = build();
    final Memory buffer = hopByHopOptions.buffer();
    Assertions.assertEquals(0, buffer.readerIndex());
    Assertions.assertEquals(hopByHopOptions.header().length() + 2, buffer.writerIndex());
    Assertions.assertTrue(buffer instanceof PooledDirectByteBuffer);

    final HopByHopOptions fromBuffer = HopByHopOptions.newPacket(buffer);
    HopByHopOptions.Header header = hopByHopOptions.header();
    HopByHopOptions.Header headerFromBuffer = fromBuffer.header();
    Assertions.assertEquals(header, headerFromBuffer);

    buffer.release(); // don't forget to release the buffer to the pool
    Memory noCopyBuffer =
        headerFromBuffer
            .buffer(); // this buffer is unuseabale because it's already released to the pool.
    Assertions.assertEquals(buffer.capacity(), noCopyBuffer.capacity());
    Assertions.assertEquals(buffer.maxCapacity(), noCopyBuffer.maxCapacity());
    Assertions.assertThrows(IllegalStateException.class, () -> noCopyBuffer.release());
  }

  @Test
  public void mutateBuffer() {
    final HopByHopOptions pkt = build();
    final Memory buffer = pkt.buffer();

    HopByHopOptions mutate =
        HopByHopOptions.newPacket(buffer)
            .builder()
            .nextHeader(TransportLayer.TCP)
            .options(new byte[] {2, 2, 3, 4, 5, 1})
            .reset()
            .build();

    buffer.readerIndex(0);
    buffer.writerIndex(buffer.writerIndex() + 2);
    HopByHopOptions mutated = HopByHopOptions.newPacket(buffer);

    Assertions.assertEquals(mutate.header(), mutated.header());
    Assertions.assertEquals(mutate.header().hashCode(), mutated.header().hashCode());

    Assertions.assertEquals(((PooledDirectByteBuffer) buffer).refCnt(), 1);
    Assertions.assertTrue(buffer.release()); // release buffer to the pool
    Assertions.assertEquals(mutate.buffer().capacity(), mutated.buffer().capacity());
    Assertions.assertEquals(mutate.buffer().maxCapacity(), mutated.buffer().maxCapacity());
    Assertions.assertThrows(IllegalStateException.class, () -> mutate.buffer().release());
  }

  @Test
  public void toStringTest() {
    HopByHopOptions pkt = build();
    Assertions.assertNotNull(pkt.toString());
  }

  @AfterEach
  public void after() {
    try {
      buf.release();
    } catch (Throwable e) {
      //
    }
  }
}
