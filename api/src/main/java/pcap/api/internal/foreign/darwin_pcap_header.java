/** This code is licenced under the GPL version 2. */
package pcap.api.internal.foreign;

import java.foreign.annotations.NativeFunction;
import java.foreign.annotations.NativeHeader;
import java.foreign.memory.Callback;
import java.foreign.memory.Pointer;
import pcap.api.internal.foreign.callback.darwin_callback;
import pcap.api.internal.foreign.struct.darwin_structs;

/**
 * Darwin pcap api mapping.
 *
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 */
@NativeHeader(resolutionContext = {darwin_structs.pcap_pkthdr.class, darwin_structs.timeval.class})
public interface darwin_pcap_header {

  @NativeFunction("(u64:${pcap})i32")
  int pcap_get_selectable_fd(Pointer<pcap_header.pcap> p);

  @NativeFunction("(u64:${pcap}i32u64:(u64:u8u64:${pcap_pkthdr}u64:u8)vu64:u8)i32")
  int pcap_loop(
      Pointer<pcap_header.pcap> p,
      int cnt,
      Callback<darwin_callback.pcap_handler> callback,
      Pointer<Byte> usr);

  @NativeFunction("(u64:${pcap}i32u64:(u64:u8u64:${pcap_pkthdr}u64:u8)vu64:u8)i32")
  int pcap_dispatch(
      Pointer<pcap_header.pcap> p,
      int cnt,
      Callback<darwin_callback.pcap_handler> usr,
      Pointer<Byte> pp);

  @NativeFunction("(u64:${pcap}u64:u64:${pcap_pkthdr}u64:u64:u8)i32")
  int pcap_next_ex(
      Pointer<pcap_header.pcap> p,
      Pointer<? extends Pointer<darwin_structs.pcap_pkthdr>> pkthdr_p,
      Pointer<? extends Pointer<Byte>> buf);

  @NativeFunction("(u64:u8u64:${pcap_pkthdr}u64:u8)v")
  void pcap_dump(Pointer<Byte> p, Pointer<darwin_structs.pcap_pkthdr> pkthdr_p, Pointer<Byte> buf);
}
