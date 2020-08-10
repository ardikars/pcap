/** This code is licenced under the GPL version 2. */
package pcap.api.internal;

import java.foreign.memory.Pointer;
import pcap.api.internal.foreign.struct.linux_structs;
import pcap.common.util.Strings;
import pcap.spi.Timestamp;

/**
 * Darwin pcap_pkthdr.
 *
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 */
public class LinuxPacketHeader implements pcap.spi.PacketHeader {

  final Pointer<Pointer<linux_structs.pcap_pkthdr>> ptr;
  final Pointer<linux_structs.pcap_pkthdr> ref;
  DefaultTimestamp timestamp;
  int captureLength;
  int length;

  public LinuxPacketHeader(
      Pointer<Pointer<linux_structs.pcap_pkthdr>> ptr,
      Pointer<linux_structs.pcap_pkthdr> ref,
      DefaultTimestamp timestamp,
      int captureLength,
      int length) {
    this.ptr = ptr;
    this.ref = ref;
    this.timestamp = timestamp;
    this.captureLength = captureLength;
    this.length = length;
  }

  @Override
  public Timestamp timestamp() {
    return timestamp;
  }

  @Override
  public int captureLength() {
    return captureLength;
  }

  @Override
  public int length() {
    return length;
  }

  @Override
  public String toString() {
    return Strings.toStringBuilder(this)
        .add("timestamp", timestamp)
        .add("captureLength", captureLength)
        .add("length", length)
        .toString();
  }
}
