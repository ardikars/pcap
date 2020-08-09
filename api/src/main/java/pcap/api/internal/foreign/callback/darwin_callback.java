/** This code is licenced under the GPL version 2. */
package pcap.api.internal.foreign.callback;

import java.foreign.annotations.NativeCallback;
import java.foreign.memory.Pointer;
import pcap.api.internal.foreign.struct.darwin_structs;
import pcap.common.annotation.Inclubating;

/**
 * Callback functions.
 *
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 */
public interface darwin_callback {

  @Inclubating
  @NativeCallback("(u64:u8u64:${pcap_pkthdr}u64:u8)v")
  @FunctionalInterface
  interface pcap_handler {

    void gotPacket(
        Pointer<Byte> user, Pointer<darwin_structs.pcap_pkthdr> header, Pointer<Byte> packets)
        throws IllegalAccessException;
  }
}
