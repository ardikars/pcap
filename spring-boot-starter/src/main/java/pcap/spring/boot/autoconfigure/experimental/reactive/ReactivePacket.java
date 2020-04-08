/** This code is licenced under the GPL version 2. */
package pcap.spring.boot.autoconfigure.experimental.reactive;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.ToString;
import pcap.spi.PacketBuffer;
import pcap.spi.PacketHeader;

@RequiredArgsConstructor
@Getter
@ToString
public class ReactivePacket<T> {

  private final PacketHeader header;
  private final PacketBuffer packetBuffer;
  private final T parameters;
}
