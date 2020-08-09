/** This code is licenced under the GPL version 2. */
package pcap.api.internal.foreign.struct;

import java.foreign.annotations.NativeGetter;
import java.foreign.annotations.NativeStruct;
import java.foreign.memory.Array;
import java.foreign.memory.Struct;

/**
 * Linux structs.
 *
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 */
public interface linux_structs {

  @NativeStruct("[u16(sa_family)[14u8](sa_data)](sockaddr)")
  interface sockaddr extends Struct<sockaddr> {

    @NativeGetter("sa_family")
    short sa_family$get();

    @NativeGetter("sa_data")
    Array<Byte> sa_data$get();
  }

  @NativeStruct("[u32(s_addr)](in_addr)")
  interface in_addr extends Struct<in_addr> {

    @NativeGetter("s_addr")
    int s_addr$get();
  }

  @NativeStruct(
      value = "[u16(sin_family)u16(sin_port)${in_addr}(sin_addr)[8u8](sin_zero)](sockaddr_in)",
      resolutionContext = in_addr.class)
  interface sockaddr_in extends Struct<sockaddr_in> {

    @NativeGetter("sin_family")
    short sin_family$get();

    @NativeGetter("sin_port")
    short sin_port$get();

    @NativeGetter("sin_addr")
    in_addr sin_addr$get();

    @NativeGetter("sin_zero")
    Array<Byte> sin_zero$get();
  }

  @NativeStruct(
      value = "[${anon$in6_u}(__in6_u)](in6_addr)",
      resolutionContext = in6_addr.anon$in6_u.class)
  interface in6_addr extends Struct<in6_addr> {

    @NativeGetter("__in6_u")
    anon$in6_u __in6_u$get();

    @NativeStruct("[[16u8](__u6_addr8)|[8u16](__u6_addr16)|[4u32](__u6_addr32)](anon$in6_u)")
    interface anon$in6_u extends Struct<anon$in6_u> {

      @NativeGetter("__u6_addr8")
      Array<Byte> __u6_addr8$get();

      @NativeGetter("__u6_addr16")
      Array<Short> __u6_addr16$get();

      @NativeGetter("__u6_addr32")
      Array<Integer> __u6_addr32$get();
    }
  }

  @NativeStruct(
      value =
          "[u16(sin6_family)u16(sin6_port)u32(sin6_flowinfo)${in6_addr}(sin6_addr)u32(sin6_scope_id)](sockaddr_in6)",
      resolutionContext = in6_addr.class)
  interface sockaddr_in6 extends Struct<sockaddr_in6> {

    @NativeGetter("sin6_family")
    short sin6_family$get();

    @NativeGetter("sin6_port")
    short sin6_port$get();

    @NativeGetter("sin6_flowinfo")
    int sin6_flowinfo$get();

    @NativeGetter("sin6_addr")
    in6_addr sin6_addr$get();

    @NativeGetter("sin6_scope_id")
    int sin6_scope_id$get();
  }

  @NativeStruct(
      value = "[${timeval}(ts)u32(caplen)u32(len)](pcap_pkthdr)",
      resolutionContext = {timeval.class})
  interface pcap_pkthdr extends Struct<pcap_pkthdr> {

    @NativeGetter("ts")
    timeval timestamp();

    @NativeGetter("caplen")
    int captureLength();

    @NativeGetter("len")
    int length();
  }

  @NativeStruct("[i64(tv_sec)i32(tv_usec)x32](timeval)")
  interface timeval extends Struct<timeval> {

    @NativeGetter("tv_sec")
    long second();

    @NativeGetter("tv_usec")
    int microSecond();
  }
}
