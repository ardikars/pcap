package pcap.api.internal.foreign;

import java.foreign.annotations.NativeFunction;
import java.foreign.annotations.NativeHeader;
import java.foreign.memory.Pointer;
import pcap.api.internal.foreign.struct.darwin_structs;
import pcap.api.internal.foreign.struct.linux_structs;

public interface backport_pcap_header {

  @NativeHeader(resolutionContext = darwin_structs.timeval.class)
  interface darwin {

    @NativeFunction("(u64:${pcap})u64:${timeval}")
    Pointer<darwin_structs.timeval> pcap_get_required_select_timeout(Pointer<pcap_header.pcap> p);
  }

  @NativeHeader(resolutionContext = linux_structs.timeval.class)
  interface linux {

    @NativeFunction("(u64:${pcap})u64:${timeval}")
    Pointer<linux_structs.timeval> pcap_get_required_select_timeout(Pointer<pcap_header.pcap> p);
  }
}
