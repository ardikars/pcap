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
import pcap.codec.ip.ip6.Routing;
import pcap.common.memory.Memory;
import pcap.common.memory.internal.nio.PooledDirectByteBuffer;
import pcap.common.util.Hexs;

/** @author <a href="mailto:contact@ardikars.com">Langkuy</a> */
@RunWith(JUnitPlatform.class)
public class Ip6RoutingTest extends BaseTest {

  private byte[] data = Hexs.parseHex(IPV6_ROUTING_UDP);

  private Memory buf = allocator.allocate(data.length);

  public Routing build() {
    Routing.Builder builder = new Routing.Builder();
    return builder
        .nextHeader(TransportLayer.TCP)
        .extensionLength(2)
        .routingType(Routing.Type.DEPRECATED_01)
        .segmentLeft(1)
        .routingData(new byte[] {0, 0, 0, 0, 34, 0, 0, 0, 0, 0, 2, 16, 0, 2, 0, 0, 0, 0, 0, 4})
        .build();
  }

  @Override
  public void before() {
    buf.writeBytes(data);
    ethernet = Ethernet.newPacket(buf);
    final Routing first = ethernet.getFirst(Routing.class);
    Memory memory = first.buffer();
    Assertions.assertEquals(0, memory.readerIndex());
    Assertions.assertEquals(first.header().length(), memory.writerIndex());
  }

  @Test
  public void buildTest() {
    final Routing authentication = build();
    final Memory buffer = authentication.buffer();

    Assertions.assertEquals(0, buffer.readerIndex());
    Assertions.assertEquals(authentication.header().length(), buffer.writerIndex());
    Assertions.assertTrue(buffer instanceof PooledDirectByteBuffer);

    final Routing fromBuffer = Routing.newPacket(buffer);
    Routing.Header header = authentication.header();
    Routing.Header headerFromBuffer = fromBuffer.header();
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
  public void mutateBufferTest() {
    final Routing pkt = build();
    final Memory buffer = pkt.buffer();

    Routing mutate =
        Routing.newPacket(buffer)
            .builder()
            .nextHeader(TransportLayer.UDP)
            .extensionLength(2)
            .routingType(Routing.Type.ALLOWED_01)
            .segmentLeft(1)
            .routingData(new byte[] {1, 1, 1, 1, 34, 0, 0, 0, 0, 0, 2, 16, 0, 2, 0, 0, 0, 0, 0, 4})
            .reset()
            .build();

    buffer.readerIndex(0);
    Routing mutated = Routing.newPacket(buffer);

    Assertions.assertEquals(mutate.header(), mutated.header());
    Assertions.assertEquals(mutate.header().hashCode(), mutated.header().hashCode());

    Assertions.assertEquals(((PooledDirectByteBuffer) buffer).refCnt(), 1);
    Assertions.assertTrue(buffer.release()); // release buffer to the pool
    Assertions.assertEquals(mutate.buffer().capacity(), mutated.buffer().capacity());
    Assertions.assertEquals(mutate.buffer().maxCapacity(), mutated.buffer().maxCapacity());
    Assertions.assertThrows(IllegalStateException.class, () -> mutate.buffer().release());
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
