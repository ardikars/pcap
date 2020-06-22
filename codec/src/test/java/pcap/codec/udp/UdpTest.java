package pcap.codec.udp;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.runner.RunWith;
import pcap.codec.BaseTest;
import pcap.codec.UnknownPacket;
import pcap.codec.ethernet.Ethernet;
import pcap.codec.ip.Ip4;
import pcap.common.memory.Memories;
import pcap.common.memory.Memory;
import pcap.common.memory.internal.nio.PooledDirectByteBuffer;
import pcap.common.net.Inet4Address;
import pcap.common.util.Hexs;

@RunWith(JUnitPlatform.class)
public class UdpTest extends BaseTest {

  private final byte[] data = Hexs.parseHex(ETHERNET_IPV4_UDP);

  private final Memory buf = allocator.allocate(data.length);

  @Override
  public void before() {
    buf.writeBytes(data);
    ethernet = Ethernet.newPacket(buf);
    final Udp first = ethernet.getFirst(Udp.class);
    Memory memory = first.buffer();
    Assertions.assertEquals(0, memory.readerIndex());
    Assertions.assertEquals(Udp.Header.UDP_HEADER_LENGTH, memory.writerIndex());
  }

  @Test
  public void checksumTest() {
    Ethernet ethernet =
        Ethernet.newPacket(
            Memories.wrap(
                "00090f090014e86f38393dbf080045000051349800004011ce2a0a0e4c730a0e174b97d30035003d807a8c710120000100000000000108617264696b61727303636f6d0000010001000029100000000000000c000a0008e1113ba1c6eb7772"));
    final Ip4 ip4 = ethernet.getFirst(Ip4.class);
    final Udp udp = ethernet.getFirst(Udp.class);

    Assertions.assertTrue(
        udp.header()
            .isValidChecksum(ip4.header().sourceAddress(), ip4.header().destinationAddress()));

    final Udp.Builder builder =
        new Udp.Builder()
            .sourcePort(udp.header().sourcePort())
            .destinationPort(udp.header().destinationPort())
            .length(udp.header().lengthUdp())
            .payload(
                new UnknownPacket.Builder()
                    .build(
                        Memories.wrap(
                            "8c710120000100000000000108617264696b61727303636f6d0000010001000029100000000000000c000a0008e1113ba1c6eb7772")))
            .calculateChecksum(
                ip4.header().sourceAddress(), ip4.header().destinationAddress(), true);
    final Udp newUdp = builder.build();
    Assertions.assertEquals(udp.header().checksum(), newUdp.header().checksum());
  }

  private Udp build() {
    final Udp.Builder builder =
        new Udp.Builder()
            .sourcePort(399)
            .destinationPort(500)
            .length(50)
            .payload(
                new UnknownPacket.Builder()
                    .build(
                        Memories.wrap(
                            "17030300220bfb2d3a2359d8377ec9e3a76cf063d4c1dbd4fdbbe8df9327b448f0f64b22e48af8")))
            .calculateChecksum(
                Inet4Address.valueOf("192.168.1.2"), Inet4Address.valueOf("192.168.1.3"), true);
    return builder.build();
  }

  @Test
  public void buildTest() {
    final Udp pkt = build();
    final Memory buffer = pkt.buffer();

    Assertions.assertEquals(0, buffer.readerIndex());
    Assertions.assertEquals(Udp.Header.UDP_HEADER_LENGTH, buffer.writerIndex());
    Assertions.assertTrue(buffer instanceof PooledDirectByteBuffer);

    final Udp fromBuffer = Udp.newPacket(buffer);
    Udp.Header header = pkt.header();
    Udp.Header headerFromBuffer = fromBuffer.header();
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
    final Udp pkt = build();
    final Memory buffer = pkt.buffer();

    Udp mutate =
        Udp.newPacket(buffer)
            .builder()
            .calculateChecksum(
                Inet4Address.valueOf("192.168.1.2"), Inet4Address.valueOf("192.168.1.3"), true)
            .reset()
            .build();

    buffer.readerIndex(0);
    Udp mutated = Udp.newPacket(buffer);

    Assertions.assertEquals(mutate.header(), mutated.header());
    Assertions.assertEquals(mutate.header().hashCode(), mutated.header().hashCode());
    Assertions.assertNotEquals(pkt.header().checksum(), mutated.header().checksum());

    Assertions.assertEquals(((PooledDirectByteBuffer) buffer).refCnt(), 1);
    Assertions.assertTrue(buffer.release()); // release buffer to the pool
    Assertions.assertEquals(mutate.buffer().capacity(), mutated.buffer().capacity());
    Assertions.assertEquals(mutate.buffer().maxCapacity(), mutated.buffer().maxCapacity());
    Assertions.assertThrows(IllegalStateException.class, () -> mutate.buffer().release());
  }

  @Test
  public void toStringTest() {
    Assertions.assertNotNull(build().toString());
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
