package pcap.api.jdk7;

import com.sun.jna.*;
import com.sun.jna.ptr.PointerByReference;
import java.lang.reflect.Method;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.util.*;

class NativeMappings {

  public static final int OK = 0;
  public static final int TRUE = 1;
  static final short AF_INET;
  static final short AF_INET6;
  private static final String LIB_NAME = "pcap";
  private static final Map<String, Object> NATIVE_LOAD_LIBRARY_OPTIONS =
      new HashMap<String, Object>();

  static {
    com.sun.jna.Native.register(NativeMappings.class, NativeLibrary.getInstance(LIB_NAME));

    // for interface mapping
    final Map<String, String> funcMap = new HashMap<String, String>();
    funcMap.put("pcap_set_rfmon", "pcap_set_rfmon");
    funcMap.put(
        "pcap_open_offline_with_tstamp_precision", "pcap_open_offline_with_tstamp_precision");
    funcMap.put("pcap_set_tstamp_precision", "pcap_set_tstamp_precision");
    funcMap.put("pcap_set_immediate_mode", "pcap_set_immediate_mode");

    NATIVE_LOAD_LIBRARY_OPTIONS.put(
        Library.OPTION_FUNCTION_MAPPER,
        new FunctionMapper() {
          @Override
          public String getFunctionName(NativeLibrary library, Method method) {
            return funcMap.get(method.getName());
          }
        });

    AF_INET = 2;
    AF_INET6 = defaultAfInet6();
  }

  private NativeMappings() {}

  static short defaultAfInet6() {
    short af_inet6 = 0;
    String afInet6 = System.getProperty("pcap.af.inet6");
    try {
      af_inet6 = (short) Integer.parseInt(afInet6);
    } catch (NumberFormatException e) {
      switch (Platform.getOSType()) {
        case Platform.MAC:
          af_inet6 = 30;
          break;
        case Platform.KFREEBSD:
          af_inet6 = 28;
          break;
        case Platform.LINUX:
          af_inet6 = 10;
          break;
        default:
          af_inet6 = 23;
      }
    }
    return af_inet6;
  }

  static native String pcap_lib_version();

  static native String pcap_statustostr(int error);

  static native Pointer pcap_geterr(Pointer p);

  static native int pcap_findalldevs(PointerByReference alldevsp, ErrorBuffer errbuf);

  static native void pcap_freealldevs(Pointer p);

  static native Pointer pcap_open_offline(String fname, ErrorBuffer errbuf);

  static native Pointer pcap_create(String device, ErrorBuffer errbuf);

  static native int pcap_set_snaplen(Pointer p, int snaplen);

  static native int pcap_set_promisc(Pointer p, int promisc);

  static native int pcap_can_set_rfmon(Pointer p);

  static native int pcap_set_timeout(Pointer p, int timeout);

  static native int pcap_set_tstamp_type(Pointer p, int tstampType);

  static native int pcap_set_buffer_size(Pointer p, int bufferSize);

  static native int pcap_activate(Pointer p);

  static native int pcap_loop(Pointer p, int cnt, pcap_handler callback, Pointer user);

  static native int pcap_dispatch(Pointer p, int cnt, pcap_handler callback, Pointer user);

  static native int pcap_sendpacket(Pointer p, ByteBuffer buf, int size);

  static native int pcap_compile(Pointer p, bpf_program fp, String str, int optimize, int netmask);

  static native int pcap_setfilter(Pointer p, bpf_program fp);

  static native void pcap_freecode(bpf_program fp);

  static native void pcap_close(Pointer p);

  static native void pcap_breakloop(Pointer p);

  static native int pcap_next_ex(Pointer p, PointerByReference h, PointerByReference data);

  static native Pointer pcap_dump_open(Pointer p, String fname);

  static native Pointer pcap_dump_open_append(Pointer p, String fname);

  static native void pcap_dump(
      Pointer user, DefaultPacketHeader header, DefaultPacketBuffer packet);

  static native int pcap_dump_flush(Pointer p);

  static native NativeLong pcap_dump_ftell(Pointer dumper);

  static native void pcap_dump_close(Pointer p);

  static native int pcap_stats(Pointer p, DefaultStatistics ps);

  static native int pcap_setdirection(Pointer p, int pcap_direction);

  static native int pcap_setnonblock(Pointer p, int nonblock, ErrorBuffer errbuf);

  static native int pcap_getnonblock(Pointer p, ErrorBuffer errbuf);

  static native int pcap_minor_version(Pointer p);

  static native int pcap_snapshot(Pointer p);

  static native int pcap_major_version(Pointer p);

  static native int pcap_is_swapped(Pointer p);

  static InetAddress inetAddress(DefaultAddress.sockaddr sockaddr) {
    if (sockaddr == null) {
      return null;
    }
    InetAddress address;
    try {
      if (sockaddr.getSaFamily() == AF_INET) {
        address = Inet4Address.getByAddress(Arrays.copyOfRange(sockaddr.sa_data, 2, 6));
      } else if (sockaddr.sa_family == AF_INET6) {
        address = Inet6Address.getByAddress(Arrays.copyOfRange(sockaddr.sa_data, 2, 18));
      } else {
        address = null;
      }
    } catch (Throwable e) {
      address = null;
    }
    return address;
  }

  interface pcap_handler extends Callback {

    void got_packet(Pointer args, DefaultPacketHeader header, DefaultPacketBuffer packet);
  }

  interface PlatformDependent extends Library {

    PlatformDependent INSTANCE =
        com.sun.jna.Native.load(LIB_NAME, PlatformDependent.class, NATIVE_LOAD_LIBRARY_OPTIONS);

    int pcap_set_rfmon(Pointer p, int rfmon);

    Pointer pcap_open_offline_with_tstamp_precision(
        String fname, int precision, ErrorBuffer errbuf);

    int pcap_set_tstamp_precision(Pointer p, int tstamp_precision);

    int pcap_set_immediate_mode(Pointer p, int immediate_mode);
  }

  public static final class ErrorBuffer extends Structure {

    public byte[] buf;

    public ErrorBuffer() {
      this(256);
    }

    public ErrorBuffer(int size) {
      this.buf = new byte[size];
    }

    @Override
    protected List<String> getFieldOrder() {
      return Arrays.asList("buf");
    }

    @Override
    public String toString() {
      return com.sun.jna.Native.toString(buf);
    }
  }

  public static class bpf_program extends Structure {

    public int bf_len;
    public bpf_insn.ByReference bf_insns;

    public bpf_program() {
      setAutoSynch(false);
    }

    @Override
    protected List<String> getFieldOrder() {
      List<String> list = new ArrayList<String>();
      list.add("bf_len");
      list.add("bf_insns");
      return list;
    }
  }

  public static class bpf_insn extends Structure {

    public short code;
    public byte jt;
    public byte jf;
    public int k;

    public bpf_insn() {
      setAutoSynch(false);
    }

    @Override
    protected List<String> getFieldOrder() {
      List<String> list = new ArrayList<String>();
      list.add("code");
      list.add("jt");
      list.add("jf");
      list.add("k");
      return list;
    }

    public static class ByReference extends bpf_insn implements Structure.ByReference {}
  }
}
