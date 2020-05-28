package pcap.codec.ethernet;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.runner.RunWith;
import pcap.codec.BaseTest;
import pcap.codec.NetworkLayer;
import pcap.common.memory.Memory;
import pcap.common.memory.internal.nio.PooledDirectByteBuffer;
import pcap.common.net.MacAddress;
import pcap.common.util.Hexs;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
@RunWith(JUnitPlatform.class)
public class EthernetTest extends BaseTest {

  private byte[] data = Hexs.parseHex(ETHERNET_II_Q_IN_Q_ARP);

  private Memory buf = allocator.allocate(data.length);

  @Override
  public void before() {
    buf.writeBytes(data);
    ethernet = Ethernet.newPacket(buf);
    Memory memory = ethernet.buffer();
    Assertions.assertEquals(0, memory.readerIndex());
    Assertions.assertEquals(Ethernet.Header.ETHERNET_HEADER_LENGTH, memory.writerIndex());
  }

  private Ethernet build() {
    final Ethernet.Builder builder = new Ethernet.Builder();
    final Ethernet pkt =
        builder
            .destinationMacAddress(MacAddress.BROADCAST)
            .sourceMacAddress(MacAddress.DUMMY)
            .ethernetType(NetworkLayer.DOT1Q_VLAN_TAGGED_FRAMES)
            .build();
    return pkt;
  }

  @Test
  public void buildTest() {
    final Ethernet pkt = build();
    final Memory buffer = pkt.buffer();

    Assertions.assertEquals(0, buffer.readerIndex());
    Assertions.assertEquals(Ethernet.Header.ETHERNET_HEADER_LENGTH, buffer.writerIndex());
    Assertions.assertTrue(buffer instanceof PooledDirectByteBuffer);

    final Ethernet fromBuffer = Ethernet.newPacket(buffer);
    Ethernet.Header header = pkt.header();
    Ethernet.Header headerFromBuffer = fromBuffer.header();
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
    final Ethernet pkt = build();
    final Memory buffer = pkt.buffer();

    Ethernet mutate =
        Ethernet.newPacket(buffer)
            .builder()
            .destinationMacAddress(MacAddress.valueOf("de:ad:be:ef:c0:ff"))
            .sourceMacAddress(MacAddress.valueOf("de:ad:be:ef:c0:aa"))
            .reset()
            .build();

    buffer.readerIndex(0);
    Ethernet mutated = Ethernet.newPacket(buffer);

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
    final Ethernet pkt = build();
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
