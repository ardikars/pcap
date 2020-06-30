/** This code is licenced under the GPL version 2. */
package pcap.api.internal.foreign;

import java.foreign.annotations.NativeFunction;
import java.foreign.annotations.NativeGetter;
import java.foreign.annotations.NativeHeader;
import java.foreign.annotations.NativeStruct;
import java.foreign.memory.Callback;
import java.foreign.memory.Pointer;
import java.foreign.memory.Struct;
import pcap.api.internal.PcapHandler;
import pcap.api.internal.PcapPacketHeader;
import pcap.api.internal.PcapStatus;
import pcap.common.annotation.Inclubating;

/**
 * Pcap api mapping.
 *
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 */
@Inclubating
@NativeHeader(resolutionContext = {PcapPacketHeader.class, PcapStatus.class})
public interface pcap_mapping {

  @NativeFunction("(u64:u8)u64:u8")
  Pointer<Byte> pcap_lookupdev(Pointer<Byte> src);

  @NativeFunction("(u64:u8u64:u8)u64:${pcap}")
  Pointer<pcap> pcap_create(Pointer<Byte> src, Pointer<Byte> errbuf);

  @NativeFunction("(u64:${pcap})i32")
  int pcap_activate(Pointer<pcap> p);

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

  @NativeFunction("(u64:${pcap}u64:u64:${pcap_pkthdr}u64:u64:u8)i32")
  int pcap_next_ex(
      Pointer<pcap> p,
      Pointer<? extends Pointer<PcapPacketHeader>> pkthdr_p,
      Pointer<? extends Pointer<Byte>> buf);

  @NativeFunction("(u64:${pcap})v")
  void pcap_breakloop(Pointer<pcap> p);

  @NativeFunction("(u64:${pcap}u64:${pcap_stat})i32")
  int pcap_stats(Pointer<pcap> p, Pointer<PcapStatus> stat_p);

  @NativeFunction("(u64:${pcap}u64:${bpf_program})i32")
  int pcap_setfilter(Pointer<pcap> p, Pointer<bpf_mapping.bpf_program> program_p);

  @NativeFunction("(u64:${pcap}i32)i32")
  int pcap_setdirection(Pointer<pcap> p, int direction);

  @NativeFunction("(u64:${pcap}i32u64:u8)i32")
  int pcap_setnonblock(Pointer<pcap> p, int var1, Pointer<Byte> var2);

  @NativeFunction("(u64:${pcap}u64:u8i32)i32")
  int pcap_sendpacket(Pointer<pcap> p, Pointer<Byte> var1, int var2);

  @NativeFunction("(i32)u64:u8")
  Pointer<Byte> pcap_statustostr(int status);

  @NativeFunction("(u64:${pcap})u64:u8")
  Pointer<Byte> pcap_geterr(Pointer<pcap> p);

  @NativeFunction("(u64:${pcap}u64:${bpf_program}u64:u8i32u32)i32")
  int pcap_compile(
      Pointer<pcap> p,
      Pointer<bpf_mapping.bpf_program> program,
      Pointer<Byte> filter,
      int var1,
      int var2);

  @NativeFunction("(u64:${bpf_program})v")
  void pcap_freecode(Pointer<bpf_mapping.bpf_program> program);

  @NativeFunction("(u64:${pcap})i32")
  int pcap_datalink(Pointer<pcap> p);

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
  void pcap_dump(Pointer<Byte> p, Pointer<PcapPacketHeader> pkthdr_p, Pointer<Byte> buf);

  @NativeFunction("(u64:u64:${pcap_if}u64:u8)i32")
  int pcap_findalldevs(Pointer<? extends Pointer<pcap_if>> alldevs, Pointer<Byte> errbuf);

  @NativeFunction("(u64:${pcap_if})v")
  void pcap_freealldevs(Pointer<pcap_if> alldevs);

  @NativeFunction("()u64:u8")
  Pointer<Byte> pcap_lib_version();

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

  @NativeStruct(
      "[u64(next):${pcap_addr}u64(addr):${sockaddr}u64(netmask):${sockaddr}u64(broadaddr):${sockaddr}u64(dstaddr):${sockaddr}](pcap_addr)")
  interface pcap_addr extends Struct<pcap_addr> {

    @NativeGetter("next")
    Pointer<pcap_addr> next$get();

    @NativeGetter("addr")
    Pointer<struct_mapping.sockaddr> addr$get();

    @NativeGetter("netmask")
    Pointer<struct_mapping.sockaddr> netmask$get();

    @NativeGetter("broadaddr")
    Pointer<struct_mapping.sockaddr> broadaddr$get();

    @NativeGetter("dstaddr")
    Pointer<struct_mapping.sockaddr> dstaddr$get();
  }
}
