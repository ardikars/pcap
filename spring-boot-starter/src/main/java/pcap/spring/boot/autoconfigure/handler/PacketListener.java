/** This code is licenced under the GPL version 2. */
package pcap.spring.boot.autoconfigure.handler;

import pcap.spi.PacketHeader;

interface PacketListener<T, P> {

  void next(T args, PacketHeader header, P packet);
}
