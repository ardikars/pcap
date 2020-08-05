/** This code is licenced under the GPL version 2. */
package pcap.api.internal.foreign;

import java.foreign.annotations.NativeFunction;
import java.foreign.annotations.NativeHeader;
import java.foreign.memory.Pointer;
import pcap.api.internal.Timestamp;

/**
 * Pcap unix api mapping.
 *
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 */
@NativeHeader(resolutionContext = Timestamp.class)
public interface unix_pcap_header {

  @NativeFunction("(u64:${pcap})i32")
  int pcap_get_selectable_fd(Pointer<pcap_header.pcap> p);

  @NativeFunction("(u64:${pcap})u64:${timeval}")
  Pointer<Timestamp> pcap_get_required_select_timeout(Pointer<pcap_header.pcap> p);
}
