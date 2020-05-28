/** This code is licenced under the GPL version 2. */
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
import pcap.common.util.Hexs;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
@RunWith(JUnitPlatform.class)
public class VlanTest extends BaseTest {

  private byte[] data = Hexs.parseHex(ETHERNET_II_Q_IN_Q_ARP);

  private Memory buf = allocator.allocate(data.length);

  @Override
  public void before() {
    buf.writeBytes(data);
    ethernet = Ethernet.newPacket(buf);
    final Vlan first = ethernet.getFirst(Vlan.class);
    Memory memory = first.buffer();
    Assertions.assertEquals(0, memory.readerIndex());
    Assertions.assertEquals(Vlan.Header.VLAN_HEADER_LENGTH, memory.writerIndex());
  }

  private Vlan build() {
    final Vlan.Builder builder = new Vlan.Builder();
    final Vlan pkt =
        builder
            .priorityCodePoint(Vlan.PriorityCodePoint.BE)
            .canonicalFormatIndicator(0)
            .vlanIdentifier(100)
            .type(NetworkLayer.ARP)
            .build();
    return pkt;
  }

  @Test
  public void buildTest() {
    final Vlan pkt = build();
    final Memory buffer = pkt.buffer();

    Assertions.assertEquals(0, buffer.readerIndex());
    Assertions.assertEquals(Vlan.Header.VLAN_HEADER_LENGTH, buffer.writerIndex());
    Assertions.assertTrue(buffer instanceof PooledDirectByteBuffer);

    final Vlan fromBuffer = Vlan.newPacket(buffer);
    Vlan.Header header = pkt.header();
    Vlan.Header headerFromBuffer = fromBuffer.header();
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
    final Vlan pkt = build();
    final Memory buffer = pkt.buffer();

    Vlan mutate =
        Vlan.newPacket(buffer)
            .builder()
            .canonicalFormatIndicator(1)
            .vlanIdentifier(2)
            .priorityCodePoint(Vlan.PriorityCodePoint.BK)
            .reset()
            .build();

    buffer.readerIndex(0);
    Vlan mutated = Vlan.newPacket(buffer);

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
    final Vlan pkt = build();
    Assertions.assertNotNull(pkt.toString());
  }

  @Test
  public void registerPriorityCodePointTest() {
    Assertions.assertEquals(
        new Vlan.PriorityCodePoint((byte) -1, "Unknown"), Vlan.PriorityCodePoint.valueOf((byte) 8));
    Vlan.PriorityCodePoint newUnknownPCP = new Vlan.PriorityCodePoint((byte) 8, "New Unknown");
    Vlan.PriorityCodePoint.register(newUnknownPCP);
    Assertions.assertEquals(newUnknownPCP, Vlan.PriorityCodePoint.valueOf((byte) 8));
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
