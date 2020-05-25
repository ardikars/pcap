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
import pcap.common.memory.Memory;
import pcap.common.memory.internal.nio.PooledDirectByteBuffer;
import pcap.common.net.Inet4Address;
import pcap.common.util.Hexs;

@RunWith(JUnitPlatform.class)
public class Ip4TcpTest extends BaseTest {

  private final byte[] data = Hexs.parseHex(ETHERNET_IPV4_TCP_SYN);

  private final Memory buf = allocator.allocate(data.length);

  @Override
  public void before() {
    buf.writeBytes(data);
    ethernet = Ethernet.newPacket(buf);
  }

  private Ip4 build() {
    final Ip4.Builder builder = new Ip4.Builder();
    final Ip4 pkt =
        builder
            .headerLength(Ip4.Header.IPV4_HEADER_LENGTH)
            .diffServ(0x0)
            .expCon(1)
            .totalLength(40)
            .identification(0xf492)
            .flags(0x4000)
            .fragmentOffset(0)
            .ttl(253)
            .protocol(TransportLayer.TCP)
            .calculateChecksum(true)
            .sourceAddress(Inet4Address.valueOf("192.168.1.1"))
            .destinationAddress(Inet4Address.valueOf("192.168.1.2"))
            .options(new byte[] { })
            .build();
    return pkt;
  }

  @Test
  public void buildTest() {
    final Ip4 ip4 = build();
    final Memory buffer = ip4.buffer();

    Assertions.assertEquals(0, buffer.readerIndex());
    Assertions.assertEquals(Ip4.Header.IPV4_HEADER_LENGTH, buffer.writerIndex());
    Assertions.assertTrue(buffer instanceof PooledDirectByteBuffer);

    final Ip4 fromBuffer = Ip4.newPacket(buffer);
    Ip4.Header header = ip4.header();
    Ip4.Header headerFromBuffer = fromBuffer.header();
    Assertions.assertEquals(header, headerFromBuffer);

    Memory noCopyBuffer = headerFromBuffer.buffer();
    Assertions.assertEquals(buffer.capacity(), noCopyBuffer.capacity());
    Assertions.assertEquals(buffer.maxCapacity(), noCopyBuffer.maxCapacity());

    Assertions.assertEquals(((PooledDirectByteBuffer) buffer).refCnt(), 1);
    Assertions.assertTrue(buffer.release()); // release buffer to the pool
  }

  @Test
  public void mutateBuffer() {
    final Ip4 pkt = build();
    final Memory buffer = pkt.buffer();

    Ip4 mutate =
        Ip4.newPacket(buffer)
            .builder()
            .ttl(128)
            .protocol(TransportLayer.UDP)
            .calculateChecksum(true)
            .sourceAddress(Inet4Address.valueOf("192.168.1.2"))
            .destinationAddress(Inet4Address.valueOf("192.168.1.1"))
            .reset()
            .build();

    buffer.readerIndex(0);
    Ip4 mutated = Ip4.newPacket(buffer);

    Assertions.assertEquals(mutate.header(), mutated.header());
    Assertions.assertEquals(mutate.header().hashCode(), mutated.header().hashCode());

    Assertions.assertEquals(((PooledDirectByteBuffer) buffer).refCnt(), 1);
    Assertions.assertTrue(buffer.release()); // release buffer to the pool
    Assertions.assertEquals(mutate.buffer().capacity(), mutated.buffer().capacity());
    Assertions.assertEquals(mutate.buffer().maxCapacity(), mutated.buffer().maxCapacity());
  }

  @Test
  public void toStringTest() {
    Ip4 pkt = build();
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
