package pcap.codec;

import java.util.Iterator;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.runner.RunWith;
import pcap.codec.ethernet.Ethernet;
import pcap.codec.ip.Ip4;
import pcap.codec.tcp.Tcp;
import pcap.common.memory.Memory;
import pcap.common.memory.MemoryAllocator;
import pcap.common.memory.exception.NoSuchMemoryAllocatorException;
import pcap.common.util.Hexs;

@RunWith(JUnitPlatform.class)
public class PacketPipelineTest {

  @Test
  public void addHandlerTest() {
    PacketPipeline pipeline = PacketPipeline.Creator.create();
    pipeline.addLast(new Ip4Handler());
    pipeline.addFirst(new EthernetHandler());
    pipeline.addLast(new TcpHandler());
    pipeline.addLast(new TcpHandler());
    final Iterator<PacketPipeline.PacketHandler> iterator = pipeline.iterator();
    Assertions.assertEquals(iterator.next().type(), Ethernet.class);
    Assertions.assertEquals(iterator.next().type(), Ip4.class);
    Assertions.assertEquals(iterator.next().type(), Tcp.class);
    Assertions.assertEquals(iterator.next().type(), Tcp.class);
  }

  @Test
  public void addNonShareadbleHandlerTest() {
    final PacketPipeline pipeline = PacketPipeline.Creator.create();
    pipeline.addFirst(new EthernetHandler());
    Assertions.assertThrows(
        UnsupportedOperationException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            pipeline.addFirst(new EthernetHandler());
          }
        });
  }

  @Test
  public void startPipelineTest() throws NoSuchMemoryAllocatorException {
    final byte[] data =
        Hexs.parseHex(
            "8c8590c30b33ce9f7a7bd74e08004500002827194000fd0636a70378304dc0a82ba201bbdb948a599b5fe9edcc3350105290840a0000");
    Memory memory =
        MemoryAllocator.Creator.create("NioDirectMemoryAllocator").allocate(data.length);
    memory.writeBytes(data);

    DataLinkLayer.register(DataLinkLayer.EN10MB, new Ethernet.Builder());
    NetworkLayer.register(NetworkLayer.IPV4, new Ip4.Builder());
    TransportLayer.register(TransportLayer.TCP, new Tcp.Builder());

    PacketPipeline pipeline = PacketPipeline.Creator.create();
    pipeline.addLast(new Ip4Handler());
    pipeline.addFirst(new EthernetHandler());
    pipeline.addLast(new TcpHandler());
    pipeline.addLast(new TcpHandler());

    pipeline.start(DataLinkLayer.EN10MB, memory);
  }

  static class EthernetHandler extends PacketPipeline.AbstractPacketHandler<Ethernet> {

    @Override
    public void handle(Ethernet packet) {
      Assertions.assertNotNull(packet);
    }

    @Override
    public Class<Ethernet> type() {
      return Ethernet.class;
    }
  }

  static class Ip4Handler extends PacketPipeline.AbstractPacketHandler<Ip4> {

    @Override
    public void handle(Ip4 packet) {
      Assertions.assertNotNull(packet);
    }

    @Override
    public Class<Ip4> type() {
      return Ip4.class;
    }
  }

  @PacketPipeline.PacketHandler.Sharable
  static class TcpHandler extends PacketPipeline.AbstractPacketHandler<Tcp> {

    @Override
    public void handle(Tcp packet) {
      Assertions.assertNotNull(packet);
    }

    @Override
    public Class<Tcp> type() {
      return Tcp.class;
    }
  }
}
