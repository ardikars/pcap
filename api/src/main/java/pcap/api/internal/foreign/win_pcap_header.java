package pcap.api.internal.foreign;

import java.foreign.annotations.NativeFunction;
import java.foreign.annotations.NativeHeader;
import java.foreign.memory.Pointer;

@NativeHeader
public interface win_pcap_header {

    @NativeFunction("(u64:${pcap})u64:v")
    Pointer<Void> pcap_getevent(Pointer<pcap_header.pcap> p);
}
