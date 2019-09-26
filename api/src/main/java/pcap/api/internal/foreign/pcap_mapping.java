/** This code is licenced under the GPL version 2. */
package pcap.api.internal.foreign;

import java.foreign.annotations.NativeFunction;
import java.foreign.annotations.NativeGetter;
import java.foreign.annotations.NativeHeader;
import java.foreign.annotations.NativeStruct;
import java.foreign.memory.Array;
import java.foreign.memory.Callback;
import java.foreign.memory.Pointer;
import java.foreign.memory.Struct;
import pcap.api.internal.PcapHandler;
import pcap.api.internal.PcapPktHdr;
import pcap.api.internal.PcapStat;
import pcap.common.annotation.Inclubating;

/**
 * Pcap api mapping.
 *
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 */
@Inclubating
@NativeHeader(resolutionContext = {PcapPktHdr.class, PcapStat.class})
public interface pcap_mapping {

  @NativeFunction("(u64:u8)u64:u8")
  Pointer<Byte> pcap_lookupdev(Pointer<Byte> src);

  @NativeFunction("(u64:u8u64:u32u64:u32u64:u8)i32")
  int pcap_lookupnet(
      Pointer<Byte> src, Pointer<Integer> var1, Pointer<Integer> var2, Pointer<Byte> var3);

  @NativeFunction("(u64:u8u64:u8)u64:${pcap}")
  Pointer<pcap> pcap_create(Pointer<Byte> src, Pointer<Byte> errbuf);

  @NativeFunction("(u64:${pcap}i32)i32")
  int pcap_set_snaplen(Pointer<pcap> p, int snaplen);

  @NativeFunction("(u64:${pcap}i32)i32")
  int pcap_set_promisc(Pointer<pcap> p, int promisc);

  @NativeFunction("(u64:${pcap})i32")
  int pcap_can_set_rfmon(Pointer<pcap> p);

  @NativeFunction("(u64:${pcap}i32)i32")
  int pcap_set_rfmon(Pointer<pcap> p, int rfmon);

  @NativeFunction("(u64:${pcap}i32)i32")
  int pcap_set_timeout(Pointer<pcap> p, int timeout);

  @NativeFunction("(u64:${pcap}i32)i32")
  int pcap_set_tstamp_type(Pointer<pcap> p, int tstamp_type);

  @NativeFunction("(u64:${pcap}i32)i32")
  int pcap_set_immediate_mode(Pointer<pcap> p, int immediate_mode);

  @NativeFunction("(u64:${pcap}i32)i32")
  int pcap_set_buffer_size(Pointer<pcap> p, int buffer_size);

  @NativeFunction("(u64:${pcap}i32)i32")
  int pcap_set_tstamp_precision(Pointer<pcap> p, int tstamp_precision);

  @NativeFunction("(u64:${pcap})i32")
  int pcap_get_tstamp_precision(Pointer<pcap> p);

  @NativeFunction("(u64:${pcap})i32")
  int pcap_activate(Pointer<pcap> p);

  @NativeFunction("(u64:${pcap}u64:u64:i32)i32")
  int pcap_list_tstamp_types(Pointer<pcap> p, Pointer<? extends Pointer<Integer>> tstamp_types);

  @NativeFunction("(u64:i32)v")
  void pcap_free_tstamp_types(Pointer<Integer> p);

  @NativeFunction("(u64:u8)i32")
  int pcap_tstamp_type_name_to_val(Pointer<Byte> p);

  @NativeFunction("(i32)u64:u8")
  Pointer<Byte> pcap_tstamp_type_val_to_name(int tstamp_type);

  @NativeFunction("(i32)u64:u8")
  Pointer<Byte> pcap_tstamp_type_val_to_description(int tstamp_type);

  @NativeFunction("(u64:u8i32i32i32u64:u8)u64:${pcap}")
  Pointer<pcap> pcap_open_live(
      Pointer<Byte> src, int snaplen, int promisc, int timeout, Pointer<Byte> errbuf);

  @NativeFunction("(i32i32)u64:${pcap}")
  Pointer<pcap> pcap_open_dead(int linktype, int var1);

  @NativeFunction("(i32i32u32)u64:${pcap}")
  Pointer<pcap> pcap_open_dead_with_tstamp_precision(int linktype, int var1, int var2);

  @NativeFunction("(u64:u8u32u64:u8)u64:${pcap}")
  Pointer<pcap> pcap_open_offline_with_tstamp_precision(
      Pointer<Byte> p, int var1, Pointer<Byte> var2);

  @NativeFunction("(u64:u8u64:u8)u64:${pcap}")
  Pointer<pcap> pcap_open_offline(Pointer<Byte> p, Pointer<Byte> file);

  @NativeFunction("(u64:${pcap})v")
  void pcap_close(Pointer<pcap> p);

  @NativeFunction("(u64:${pcap}i32u64:(u64:u8u64:${pcap_pkthdr}u64:u8)vu64:u8)i32")
  int pcap_loop(Pointer<pcap> p, int cnt, Callback<PcapHandler> callback, Pointer<Byte> usr);

  @NativeFunction("(u64:${pcap}i32u64:(u64:u8u64:${pcap_pkthdr}u64:u8)vu64:u8)i32")
  int pcap_dispatch(Pointer<pcap> p, int cnt, Callback<PcapHandler> usr, Pointer<Byte> pp);

  @NativeFunction("(u64:${pcap}u64:${pcap_pkthdr})u64:u8")
  Pointer<Byte> pcap_next(Pointer<pcap> p, Pointer<PcapPktHdr> pkthdr_p);

  @NativeFunction("(u64:${pcap}u64:u64:${pcap_pkthdr}u64:u64:u8)i32")
  int pcap_next_ex(
      Pointer<pcap> p,
      Pointer<? extends Pointer<PcapPktHdr>> pkthdr_p,
      Pointer<? extends Pointer<Byte>> buf);

  @NativeFunction("(u64:${pcap})v")
  void pcap_breakloop(Pointer<pcap> p);

  @NativeFunction("(u64:${pcap}u64:${pcap_stat})i32")
  int pcap_stats(Pointer<pcap> p, Pointer<PcapStat> stat_p);

  @NativeFunction("(u64:${pcap}u64:${bpf_program})i32")
  int pcap_setfilter(Pointer<pcap> p, Pointer<bpf_mapping.bpf_program> program_p);

  @NativeFunction("(u64:${pcap}i32)i32")
  int pcap_setdirection(Pointer<pcap> p, int direction);

  @NativeFunction("(u64:${pcap}u64:u8)i32")
  int pcap_getnonblock(Pointer<pcap> p, Pointer<Byte> var1);

  @NativeFunction("(u64:${pcap}i32u64:u8)i32")
  int pcap_setnonblock(Pointer<pcap> p, int var1, Pointer<Byte> var2);

  @NativeFunction("(u64:${pcap}u64:vu64)i32")
  int pcap_inject(Pointer<pcap> p, Pointer<?> var1, long var2);

  @NativeFunction("(u64:${pcap}u64:u8i32)i32")
  int pcap_sendpacket(Pointer<pcap> p, Pointer<Byte> var1, int var2);

  @NativeFunction("(i32)u64:u8")
  Pointer<Byte> pcap_statustostr(int status);

  @NativeFunction("(i32)u64:u8")
  Pointer<Byte> pcap_strerror(int status);

  @NativeFunction("(u64:${pcap})u64:u8")
  Pointer<Byte> pcap_geterr(Pointer<pcap> p);

  @NativeFunction("(u64:${pcap}u64:u8)v")
  void pcap_perror(Pointer<pcap> p, Pointer<Byte> err);

  @NativeFunction("(u64:${pcap}u64:${bpf_program}u64:u8i32u32)i32")
  int pcap_compile(
      Pointer<pcap> p,
      Pointer<bpf_mapping.bpf_program> program,
      Pointer<Byte> filter,
      int var1,
      int var2);

  @NativeFunction("(i32i32u64:${bpf_program}u64:u8i32u32)i32")
  int pcap_compile_nopcap(
      int var1,
      int var2,
      Pointer<bpf_mapping.bpf_program> program,
      Pointer<Byte> filter,
      int var3,
      int var4);

  @NativeFunction("(u64:${bpf_program})v")
  void pcap_freecode(Pointer<bpf_mapping.bpf_program> program);

  @NativeFunction("(u64:${bpf_program}u64:${pcap_pkthdr}u64:u8)i32")
  int pcap_offline_filter(
      Pointer<bpf_mapping.bpf_program> program, Pointer<PcapPktHdr> pkthdr_p, Pointer<Byte> filter);

  @NativeFunction("(u64:${pcap})i32")
  int pcap_datalink(Pointer<pcap> p);

  @NativeFunction("(u64:${pcap})i32")
  int pcap_datalink_ext(Pointer<pcap> p);

  @NativeFunction("(u64:${pcap}u64:u64:i32)i32")
  int pcap_list_datalinks(Pointer<pcap> p, Pointer<? extends Pointer<Integer>> datalinks);

  @NativeFunction("(u64:${pcap}i32)i32")
  int pcap_set_datalink(Pointer<pcap> p, int datalink);

  @NativeFunction("(u64:i32)v")
  void pcap_free_datalinks(Pointer<Integer> datalinks);

  @NativeFunction("(u64:u8)i32")
  int pcap_datalink_name_to_val(Pointer<Byte> dtl_name);

  @NativeFunction("(i32)u64:u8")
  Pointer<Byte> pcap_datalink_val_to_name(int dtl_val);

  @NativeFunction("(i32)u64:u8")
  Pointer<Byte> pcap_datalink_val_to_description(int dtl_var);

  @NativeFunction("(u64:${pcap})i32")
  int pcap_snapshot(Pointer<pcap> p);

  @NativeFunction("(u64:${pcap})i32")
  int pcap_is_swapped(Pointer<pcap> p);

  @NativeFunction("(u64:${pcap})i32")
  int pcap_major_version(Pointer<pcap> p);

  @NativeFunction("(u64:${pcap})i32")
  int pcap_minor_version(Pointer<pcap> p);

  @NativeFunction("(u64:${pcap})i32")
  int pcap_fileno(Pointer<pcap> p);

  @NativeFunction("(u64:${pcap}u64:u8)u64:${pcap_dumper}")
  Pointer<pcap_dumper> pcap_dump_open(Pointer<pcap> p, Pointer<Byte> file);

  @NativeFunction("(u64:${pcap}u64:u8)u64:${pcap_dumper}")
  Pointer<pcap_dumper> pcap_dump_open_append(Pointer<pcap> p, Pointer<Byte> var1);

  @NativeFunction("(u64:${pcap_dumper})i64")
  long pcap_dump_ftell(Pointer<pcap_dumper> p);

  @NativeFunction("(u64:${pcap_dumper})i32")
  int pcap_dump_flush(Pointer<pcap_dumper> p);

  @NativeFunction("(u64:${pcap_dumper})v")
  void pcap_dump_close(Pointer<pcap_dumper> p);

  @NativeFunction("(u64:u8u64:${pcap_pkthdr}u64:u8)v")
  void pcap_dump(Pointer<Byte> p, Pointer<PcapPktHdr> pkthdr_p, Pointer<Byte> buf);

  @NativeFunction("(u64:u64:${pcap_if}u64:u8)i32")
  int pcap_findalldevs(Pointer<? extends Pointer<pcap_if>> alldevs, Pointer<Byte> errbuf);

  @NativeFunction("(u64:${pcap_if})v")
  void pcap_freealldevs(Pointer<pcap_if> alldevs);

  @NativeFunction("()u64:u8")
  Pointer<Byte> pcap_lib_version();

  @NativeFunction("(u64:${bpf_insn}u64:u8u32u32)u32")
  int bpf_filter(Pointer<bpf_mapping.bpf_insn> insn_p, Pointer<Byte> p, int var1, int var2);

  @NativeFunction("(u64:${bpf_insn}i32)i32")
  int bpf_validate(Pointer<bpf_mapping.bpf_insn> f, int len);

  @NativeFunction("(u64:${bpf_insn}i32)u64:u8")
  Pointer<Byte> bpf_image(Pointer<bpf_mapping.bpf_insn> insn_p, int var1);

  @NativeFunction("(u64:${bpf_program}i32)v")
  void bpf_dump(Pointer<bpf_mapping.bpf_program> program_p, int var2);

  @NativeFunction("(u64:${pcap})i32")
  int pcap_get_selectable_fd(Pointer<pcap> p);

  @NativeStruct("${pcap}")
  interface pcap extends Struct<pcap> {}

  @NativeStruct("${pcap_dumper}")
  interface pcap_dumper extends Struct<pcap_dumper> {}

  @NativeStruct(
      "[u64(next):${pcap_if}u64(name):u8u64(description):u8u64(addresses):${pcap_addr}u32(flags)x32](pcap_if)")
  interface pcap_if extends Struct<pcap_if> {

    @NativeGetter("next")
    Pointer<pcap_if> next$get();

    @NativeGetter("name")
    Pointer<Byte> name$get();

    @NativeGetter("description")
    Pointer<Byte> description$get();

    @NativeGetter("addresses")
    Pointer<pcap_addr> addresses$get();

    @NativeGetter("flags")
    int flags$get();
  }

  @NativeStruct("[u8(sa_len)u8(sa_family)[18u8](sa_data)](sockaddr)")
  interface sockaddr extends Struct<sockaddr> {

    @NativeGetter("sa_len")
    byte sa_len$get();

    @NativeGetter("sa_family")
    byte sa_family$get();

    @NativeGetter("sa_data")
    Array<Byte> sa_data$get();
  }

  @NativeStruct(
      "[u64(next):${pcap_addr}u64(addr):${sockaddr}u64(netmask):${sockaddr}u64(broadaddr):${sockaddr}u64(dstaddr):${sockaddr}](pcap_addr)")
  interface pcap_addr extends Struct<pcap_addr> {

    @NativeGetter("next")
    Pointer<pcap_addr> next$get();

    @NativeGetter("addr")
    Pointer<sockaddr> addr$get();

    @NativeGetter("netmask")
    Pointer<sockaddr> netmask$get();

    @NativeGetter("broadaddr")
    Pointer<sockaddr> broadaddr$get();

    @NativeGetter("dstaddr")
    Pointer<sockaddr> dstaddr$get();
  }
}
