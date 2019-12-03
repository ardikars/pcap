/** This code is licenced under the GPL version 2. */
package pcap.api.internal;

import java.foreign.annotations.NativeGetter;
import java.foreign.annotations.NativeStruct;
import java.foreign.memory.Pointer;
import java.foreign.memory.Struct;
import pcap.common.annotation.Inclubating;
import pcap.spi.PacketHeader;

/**
 * Wrapper for {@code pcap_pkthdr}
 *
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 */
@Inclubating
@NativeStruct(
    value = "[${timeval}(ts)u32(caplen)u32(len)](pcap_pkthdr)",
    resolutionContext = {Timestamp.class})
public interface PcapPacketHeader extends Struct<PcapPacketHeader> {

  @NativeGetter("ts")
  Timestamp timestamp();

  @NativeGetter("caplen")
  int captureLength();

  @NativeGetter("len")
  int length();

  default PacketHeader packetHeader() {
    return new Impl(timestamp().timestamp(), captureLength(), length(), ptr());
  }

  class Impl implements PacketHeader {

    private final pcap.spi.Timestamp timestamp;
    private final int captureLangth;
    private final int length;
    private final Pointer<PcapPacketHeader> ptr;

    private Impl(
        pcap.spi.Timestamp timestamp,
        int captureLangth,
        int length,
        Pointer<PcapPacketHeader> ptr) {
      this.timestamp = timestamp;
      this.captureLangth = captureLangth;
      this.length = length;
      this.ptr = ptr;
    }

    @Override
    public pcap.spi.Timestamp timestamp() {
      return timestamp;
    }

    @Override
    public int captureLength() {
      return captureLangth;
    }

    @Override
    public int length() {
      return length;
    }

    public Pointer<PcapPacketHeader> pointer() {
      return ptr;
    }
  }
}
