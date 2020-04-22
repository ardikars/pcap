package pcap.spring.boot.autoconfigure.handler;

import java.nio.ByteBuffer;
import pcap.common.util.Hexs;
import pcap.spi.PacketBuffer;
import pcap.spi.PacketHandler;
import pcap.spi.PacketHeader;

/**
 * Decode raw packet into hex string.
 *
 * @param <T> args type.
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 */
public interface HexStringHandler<T> extends PacketHandler<T> {

  @Override
  default void gotPacket(T args, PacketHeader header, PacketBuffer buffer) {
    ByteBuffer buteBuf = buffer.buffer();
    String hex = Hexs.toHexString(buteBuf, 0, buteBuf.capacity());
    gotPacket(args, header, hex);
  }

  void gotPacket(T args, PacketHeader header, String buffer);
}
