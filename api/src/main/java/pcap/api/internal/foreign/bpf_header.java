/** This code is licenced under the GPL version 2. */
package pcap.api.internal.foreign;

import java.foreign.annotations.NativeGetter;
import java.foreign.annotations.NativeHeader;
import java.foreign.annotations.NativeStruct;
import java.foreign.memory.Pointer;
import java.foreign.memory.Struct;
import pcap.common.annotation.Inclubating;

/**
 * BPF (Berkeley Packet Filter)
 *
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 */
@Inclubating
@NativeHeader
public interface bpf_header {

  @NativeStruct("[u32(bf_len)x32u64(bf_insns):${bpf_insn}](bpf_program)")
  interface bpf_program extends Struct<bpf_program> {

    @NativeGetter("bf_len")
    int bf_len$get();

    @NativeGetter("bf_insns")
    Pointer<bpf_insn> bf_insns$get();
  }

  @NativeStruct("[u16(code)u8(jt)u8(jf)u32(k)](bpf_insn)")
  interface bpf_insn extends Struct<bpf_insn> {

    @NativeGetter("code")
    short code$get();

    @NativeGetter("jt")
    byte jt$get();

    @NativeGetter("jf")
    byte jf$get();

    @NativeGetter("k")
    int k$get();
  }

  @NativeStruct("[u16(vlan_tag_present)u16(vlan_tag)](bpf_aux_data)")
  interface bpf_aux_data extends Struct<bpf_aux_data> {

    @NativeGetter("vlan_tag_present")
    short vlan_tag_present$get();

    @NativeGetter("vlan_tag")
    short vlan_tag$get();
  }
}
