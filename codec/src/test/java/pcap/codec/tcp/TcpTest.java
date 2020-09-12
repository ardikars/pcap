package pcap.codec.tcp;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.runner.RunWith;
import pcap.codec.BaseTest;
import pcap.codec.UnknownPacket;
import pcap.codec.ethernet.Ethernet;
import pcap.codec.ip.Ip4;
import pcap.common.memory.Memory;
import pcap.common.memory.MemoryAllocator;
import pcap.common.memory.internal.nio.PooledDirectByteBuffer;
import pcap.common.net.Inet4Address;
import pcap.common.util.Hexs;

@RunWith(JUnitPlatform.class)
public class TcpTest extends BaseTest {

  private final byte[] data = Hexs.parseHex(TCP_ACK);

  private final Memory buf = allocator.allocate(data.length);

  @Override
  public void before() {
    buf.writeBytes(data);
    ethernet = Ethernet.newPacket(buf);
    final Tcp first = ethernet.getFirst(Tcp.class);
    Memory memory = first.buffer();
    Assertions.assertEquals(0, memory.readerIndex());
    Assertions.assertEquals(Tcp.Header.TCP_HEADER_LENGTH, memory.writerIndex());
  }

  @Test
  public void checksumTest() {
    Ethernet ethernet =
        Ethernet.newPacket(
            MemoryAllocator.Creator.create("NioHeapMemoryAllocator")
                .wrap(
                    Hexs.parseHex(
                        "8c8590c30b33d80d17269cee08004500005baa7f00007406c82c4a7dc85ec0a8006d01bbc82f394d0f5bf373184d80180108991a00000101080ad9dec62025cbc8a917030300220bfb2d3a2359d8377ec9e3a76cf063d4c1dbd4fdbbe8df9327b448f0f64b22e48af8")));
    final Ip4 ip4 = ethernet.getFirst(Ip4.class);
    final Tcp tcp = ethernet.getFirst(Tcp.class);

    Assertions.assertTrue(
        tcp.header()
            .isValidChecksum(ip4.header().sourceAddress(), ip4.header().destinationAddress()));

    final Tcp.Builder builder =
        new Tcp.Builder()
            .sourcePort(tcp.header().sourcePort())
            .destinationPort(tcp.header().destinationPort())
            .sequence(tcp.header().sequence())
            .acknowledge(tcp.header().acknowledge())
            .flags(tcp.header().flags())
            .options(tcp.header().options())
            .urgentPointer(tcp.header().urgentPointer())
            .windowsSize(tcp.header().windowSize())
            .dataOffset(tcp.header().dataOffset())
            .payload(
                new UnknownPacket.Builder()
                    .build(
                        MemoryAllocator.Creator.create("NioHeapMemoryAllocator")
                            .wrap(
                                Hexs.parseHex(
                                    "17030300220bfb2d3a2359d8377ec9e3a76cf063d4c1dbd4fdbbe8df9327b448f0f64b22e48af8"))))
            .calculateChecksum(
                ip4.header().sourceAddress(), ip4.header().destinationAddress(), true);
    final Tcp newTcp = builder.build();
    Assertions.assertEquals(tcp.header().checksum(), newTcp.header().checksum());
  }

  private Tcp build() {
    final Tcp.Builder builder =
        new Tcp.Builder()
            .sourcePort(399)
            .destinationPort(500)
            .sequence(0x42)
            .acknowledge(0x4fd)
            .flags(new TcpFlags.Builder().ack(true).build())
            .options(new byte[0])
            .urgentPointer(0)
            .windowsSize(0xf4)
            .dataOffset(0x8)
            .payload(
                new UnknownPacket.Builder()
                    .build(
                        MemoryAllocator.Creator.create("NioHeapMemoryAllocator")
                            .wrap(
                                Hexs.parseHex(
                                    "17030300220bfb2d3a2359d8377ec9e3a76cf063d4c1dbd4fdbbe8df9327b448f0f64b22e48af8"))))
            .calculateChecksum(
                Inet4Address.valueOf("192.168.1.2"), Inet4Address.valueOf("192.168.1.3"), true);
    return builder.build();
  }

  @Test
  public void buildTest() {
    final Tcp pkt = build();
    final Memory buffer = pkt.buffer();

    Assertions.assertEquals(0, buffer.readerIndex());
    Assertions.assertEquals(Tcp.Header.TCP_HEADER_LENGTH, buffer.writerIndex());
    Assertions.assertTrue(buffer instanceof PooledDirectByteBuffer);

    final Tcp fromBuffer = Tcp.newPacket(buffer);
    Tcp.Header header = pkt.header();
    Tcp.Header headerFromBuffer = fromBuffer.header();
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
    final Tcp pkt = build();
    final Memory buffer = pkt.buffer();

    final Tcp mutate =
        Tcp.newPacket(buffer)
            .builder()
            .windowsSize(349)
            .sequence(33)
            .calculateChecksum(
                Inet4Address.valueOf("192.168.1.2"), Inet4Address.valueOf("192.168.1.3"), true)
            .reset()
            .build();

    buffer.readerIndex(0);
    Tcp mutated = Tcp.newPacket(buffer);

    Assertions.assertEquals(mutate.header(), mutated.header());
    Assertions.assertEquals(mutate.header().hashCode(), mutated.header().hashCode());
    Assertions.assertNotEquals(pkt.header().checksum(), mutated.header().checksum());

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
