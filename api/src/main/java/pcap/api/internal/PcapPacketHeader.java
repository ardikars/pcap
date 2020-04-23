/** This code is licenced under the GPL version 2. */
package pcap.api.internal;

import pcap.common.annotation.Inclubating;
import pcap.spi.PacketHeader;

import java.foreign.annotations.NativeGetter;
import java.foreign.annotations.NativeStruct;
import java.foreign.memory.Pointer;
import java.foreign.memory.Struct;

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
    return Impl.fromReference(ptr(), timestamp().timestamp(), captureLength(), length());
  }

  class Impl implements PacketHeader {

    Pointer<Pointer<PcapPacketHeader>> ptr;
    Pointer<PcapPacketHeader> ref;
    pcap.spi.Timestamp timestamp;
    int captureLangth;
    int length;

    Impl(
        Pointer<Pointer<PcapPacketHeader>> ptr,
        Pointer<PcapPacketHeader> ref,
        pcap.spi.Timestamp timestamp,
        int captureLangth,
        int length) {
      this.ptr = ptr;
      this.ref = ref;
      this.timestamp = timestamp;
      this.captureLangth = captureLangth;
      this.length = length;
    }

    static Impl fromPointer(
        Pointer<Pointer<PcapPacketHeader>> ptr,
        pcap.spi.Timestamp timestamp,
        int captureLangth,
        int length) {
      return new Impl(ptr, ptr.get(), timestamp, captureLangth, length);
    }

    static Impl fromReference(
        Pointer<PcapPacketHeader> reference,
        pcap.spi.Timestamp timestamp,
        int captureLangth,
        int length) {
      return new Impl(null, reference, timestamp, captureLangth, length);
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

    @Override
    public String toString() {
      return "PacketHeader{"
          + "timestamp="
          + timestamp
          + ", captureLangth="
          + captureLangth
          + ", length="
          + length
          + '}';
    }
  }
}
