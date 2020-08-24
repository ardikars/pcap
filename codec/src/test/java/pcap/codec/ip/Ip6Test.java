package pcap.codec.ip;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.runner.RunWith;
import pcap.codec.BaseTest;
import pcap.codec.TransportLayer;
import pcap.codec.UnknownPacket;
import pcap.codec.ethernet.Ethernet;
import pcap.codec.ip.ip6.Authentication;
import pcap.common.memory.Memory;
import pcap.common.memory.internal.nio.PooledDirectByteBuffer;
import pcap.common.net.Inet6Address;
import pcap.common.util.Hexs;

/** @author <a href="mailto:contact@ardikars.com">Langkuy</a> */
@RunWith(JUnitPlatform.class)
class Ip6Test extends BaseTest {

  private final byte[] data = Hexs.parseHex(IPV6_AUTHENTICATION);

  private final Memory buf = allocator.allocate(data.length);

  public static Ip6 build() {
    return new Ip6.Builder()
        .trafficClass(224)
        .flowLabel(0)
        .nextHeader(TransportLayer.TCP)
        .hopLimit(1)
        .sourceAddress(Inet6Address.valueOf("fe80::1"))
        .destinationAddress(Inet6Address.valueOf("ff02::5"))
        .sourceAddress(Inet6Address.ZERO)
        .payloadLength(60)
        .payload(new UnknownPacket.Builder().build(DIRECT_ALLOCATOR.allocate(60)))
        .build();
  }

  @Override
  public void before() {
    buf.writeBytes(data);
    ethernet = Ethernet.newPacket(buf);
    final Authentication first = ethernet.getFirst(Authentication.class);
    Memory memory = first.buffer();
    Assertions.assertEquals(0, memory.readerIndex());
    Assertions.assertEquals(first.header().length(), memory.writerIndex());
  }

  @Test
  public void buildTest() {
    final Ip6 pkt = build();
    final Memory buffer = pkt.buffer();
    Assertions.assertEquals(0, buffer.readerIndex());
    Assertions.assertEquals(Ip6.Header.IPV6_HEADER_LENGTH, buffer.writerIndex());
    Assertions.assertTrue(buffer instanceof PooledDirectByteBuffer);

    final Ip6 fromBuffer = Ip6.newPacket(buffer);
    Ip6.Header header = pkt.header();
    Ip6.Header headerFromBuffer = fromBuffer.header();
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
    final Ip6 pkt = build();
    final Memory buffer = pkt.buffer();

    final Ip6 mutate =
        Ip6.newPacket(buffer)
            .builder()
            .hopLimit(3)
            .trafficClass(33)
            .flowLabel(2)
            .nextHeader(TransportLayer.UDP)
            .reset()
            .build();

    buffer.readerIndex(0);
    Ip6 mutated = Ip6.newPacket(buffer);

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
