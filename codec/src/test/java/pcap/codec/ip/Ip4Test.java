/** This code is licenced under the GPL version 2. */
package pcap.codec.ip;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
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
public class Ip4Test extends BaseTest {

  private final byte[] data = Hexs.parseHex(ETHERNET_IPV4_TCP_SYN);

  private final Memory buf = allocator.allocate(data.length);

  @Override
  public void before() {
    buf.writeBytes(data);
    ethernet = Ethernet.newPacket(buf);
    final Ip4 first = ethernet.getFirst(Ip4.class);
    Memory memory = first.buffer();
    Assertions.assertEquals(0, memory.readerIndex());
    Assertions.assertEquals(Ip4.Header.IPV4_HEADER_LENGTH, memory.writerIndex());
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
            .options(new byte[] {})
            .build();
    return pkt;
  }

  @Test
  public void checksumTest() {
    byte[] array = Hexs.parseHex(SSL_CLIENT_HELLO);
    Memory buffer = allocator.allocate(array.length);
    buffer.writeBytes(array);
    final Ip4 ip4 = Ethernet.newPacket(buffer).getFirst(Ip4.class);
    final Ip4.Header ip4Header = ip4.header();
    final Ip4.Builder ip4Builder = ip4Header.builder().calculateChecksum(true).reset();
    final Ip4.Builder newIp4Builder =
        new Ip4.Builder()
            .calculateChecksum(true)
            .destinationAddress(ip4Header.destinationAddress())
            .diffServ(ip4Header.diffServ())
            .expCon(ip4Header.expCon())
            .flags(ip4Header.flags())
            .fragmentOffset(ip4Header.fragmentOffset())
            .headerLength(ip4Header.headerLength())
            .identification(ip4Header.identification())
            .options(ip4Header.options())
            .protocol(ip4Header.protocol())
            .sourceAddress(ip4Header.sourceAddress())
            .totalLength(ip4Header.totalLength())
            .ttl(ip4Header.ttl());
    final Ip4.Header ip4NoCopy = ip4Builder.build().header();
    final Ip4 newIp4 = newIp4Builder.build();
    Assertions.assertEquals(ip4Header, newIp4.header());
    Assertions.assertEquals(ip4Header, ip4NoCopy);
    Assertions.assertTrue(ip4Header.isValidChecksum());
    Assertions.assertTrue(ip4NoCopy.isValidChecksum());
    Assertions.assertTrue(newIp4.header().isValidChecksum());
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
    final Ip4 pkt = build();
    final Memory buffer = pkt.buffer();

    final Ip4 mutate =
        Ip4.newPacket(buffer)
            .builder()
            .ttl(128)
            .protocol(TransportLayer.UDP)
            .sourceAddress(Inet4Address.valueOf("192.168.1.2"))
            .destinationAddress(Inet4Address.valueOf("192.168.1.1"))
            .calculateChecksum(true)
            .reset()
            .build();

    buffer.readerIndex(0);
    Ip4 mutated = Ip4.newPacket(buffer);

    Assertions.assertEquals(mutate.header(), mutated.header());
    Assertions.assertEquals(mutate.header().hashCode(), mutated.header().hashCode());
    Assertions.assertNotEquals(mutated.header().checksum(), pkt.header().checksum());

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
