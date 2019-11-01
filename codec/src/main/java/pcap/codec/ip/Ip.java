/** This code is licenced under the GPL version 2. */
package pcap.codec.ip;

import pcap.codec.AbstractPacket;
import pcap.common.annotation.Inclubating;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
@Inclubating
public abstract class Ip extends AbstractPacket {

  protected abstract static class AbstractPacketHeader extends Header {

    protected final byte version;

    protected AbstractPacketHeader(final byte version) {
      this.version = version;
    }

    public int version() {
      return this.version & 0xf;
    }
  }

  protected abstract static class AbstractPaketBuilder extends Builder {}
}
