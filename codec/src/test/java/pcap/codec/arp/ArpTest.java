/** This code is licenced under the GPL version 2. */
package pcap.codec.arp;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.runner.RunWith;
import pcap.codec.BaseTest;
import pcap.codec.DataLinkLayer;
import pcap.codec.NetworkLayer;
import pcap.codec.ethernet.Ethernet;
import pcap.common.memory.Memory;
import pcap.common.memory.internal.nio.PooledDirectByteBuffer;
import pcap.common.net.Inet4Address;
import pcap.common.net.MacAddress;
import pcap.common.util.Hexs;

@RunWith(JUnitPlatform.class)
public class ArpTest extends BaseTest {

  private byte[] data = Hexs.parseHex(ETHERNET_II_ARP);

  private Memory buf = allocator.allocate(data.length);

  @Override
  public void before() {
    buf.writeBytes(data);
    ethernet = Ethernet.newPacket(buf);
    final Arp first = ethernet.getFirst(Arp.class);
    Memory memory = first.buffer();
    Assertions.assertEquals(0, memory.readerIndex());
    Assertions.assertEquals(Arp.Header.ARP_HEADER_LENGTH, memory.writerIndex());
  }

  private Arp build() {
    final Arp.Builder builder = new Arp.Builder();
    final Arp pkt =
        builder
            .hardwareAddressLength(MacAddress.MAC_ADDRESS_LENGTH)
            .hardwareType(DataLinkLayer.EN10MB)
            .protocolAddressLength(Inet4Address.IPV4_ADDRESS_LENGTH)
            .protocolType(NetworkLayer.IPV4)
            .operationCode(Arp.OperationCode.ARP_REQUEST)
            .senderHardwareAddress(MacAddress.DUMMY)
            .senderProtocolAddress(Inet4Address.valueOf("192.168.1.2"))
            .targetHardwareAddress(MacAddress.ZERO)
            .targetProtocolAddress(Inet4Address.valueOf("192.168.1.1"))
            .build();
    return pkt;
  }

  @Test
  public void buildTest() {
    final Arp pkt = build();
    final Memory buffer = pkt.buffer();
    Assertions.assertEquals(0, buffer.readerIndex());
    Assertions.assertEquals(Arp.Header.ARP_HEADER_LENGTH, buffer.writerIndex());
    Assertions.assertTrue(buffer instanceof PooledDirectByteBuffer);

    final Arp fromBuffer = Arp.newPacket(buffer);
    Arp.Header header = pkt.header();
    Arp.Header headerFromBuffer = fromBuffer.header();
    Assertions.assertEquals(header, headerFromBuffer);

    buffer.release(); // don't forget to release the buffer to the pool
    final Memory noCopyBuffer =
        headerFromBuffer
            .buffer(); // this buffer is unuseabale because it's already released to the pool.
    Assertions.assertEquals(buffer.capacity(), noCopyBuffer.capacity());
    Assertions.assertEquals(buffer.maxCapacity(), noCopyBuffer.maxCapacity());
    Assertions.assertThrows(
        IllegalStateException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            noCopyBuffer.release();
          }
        });
  }

  @Test
  public void mutateBuffer() {
    final Arp pkt = build();
    final Memory buffer = pkt.buffer();

    final Arp mutate =
        Arp.newPacket(buffer)
            .builder()
            .operationCode(Arp.OperationCode.ARP_REPLY)
            .senderHardwareAddress(MacAddress.valueOf("de:ad:be:ef:ce:ce"))
            .senderProtocolAddress(Inet4Address.valueOf("192.168.1.1"))
            .targetHardwareAddress(MacAddress.DUMMY)
            .targetProtocolAddress(Inet4Address.valueOf("192.168.1.2"))
            .reset()
            .build();

    buffer.readerIndex(0);
    Arp mutated = Arp.newPacket(buffer);

    Assertions.assertEquals(mutate.header(), mutated.header());
    Assertions.assertEquals(mutate.header().hashCode(), mutated.header().hashCode());

    Assertions.assertEquals(((PooledDirectByteBuffer) buffer).refCnt(), 1);
    Assertions.assertTrue(buffer.release()); // release buffer to the pool
    Assertions.assertEquals(mutate.buffer().capacity(), mutated.buffer().capacity());
    Assertions.assertEquals(mutate.buffer().maxCapacity(), mutated.buffer().maxCapacity());
    Assertions.assertThrows(
        IllegalStateException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            mutate.buffer().release();
          }
        });
  }

  @Test
  public void toStringTest() {
    final Arp pkt = build();
    Assertions.assertNotNull(pkt.toString());
  }

  @Test
  public void registerOperationCodeTest() {
    Arp.OperationCode arpNak = new Arp.OperationCode((short) 10, "ARP-NAK");
    Arp.OperationCode.register(arpNak);
    Assertions.assertEquals(arpNak, Arp.OperationCode.valueOf((short) 10));
    Assertions.assertEquals(Arp.OperationCode.UNKNOWN, Arp.OperationCode.valueOf((short) 100));
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
