package pcap.jdk7.internal;

import com.sun.jna.*;
import com.sun.jna.ptr.PointerByReference;
import java.lang.reflect.Method;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.nio.ByteOrder;
import java.util.*;
import pcap.spi.Address;
import pcap.spi.Interface;
import pcap.spi.Timestamp;

class NativeMappings {

  static final int OK = 0;
  static final int TRUE = 1;
  static final int FALSE = 0;
  static final short AF_INET;
  static final short AF_INET6;
  static final DefaultPlatformDependent PLATFORM_DEPENDENT;
  static final boolean isWinPcap;
  private static final Map<String, Object> NATIVE_LOAD_LIBRARY_OPTIONS =
      new HashMap<String, Object>();

  static {
    com.sun.jna.Native.register(
        NativeMappings.class, NativeLibrary.getInstance(libName(Platform.isWindows())));

    // for interface mapping
    final Map<String, String> funcMap = new HashMap<String, String>();
    funcMap.put("pcap_dump_open_append", "pcap_dump_open_append");
    funcMap.put("pcap_get_tstamp_precision", "pcap_get_tstamp_precision");
    funcMap.put("pcap_set_tstamp_type", "pcap_set_tstamp_type");
    funcMap.put("pcap_set_rfmon", "pcap_set_rfmon");
    funcMap.put(
        "pcap_open_offline_with_tstamp_precision", "pcap_open_offline_with_tstamp_precision");
    funcMap.put("pcap_set_tstamp_precision", "pcap_set_tstamp_precision");
    funcMap.put("pcap_set_immediate_mode", "pcap_set_immediate_mode");
    funcMap.put("pcap_get_selectable_fd", "pcap_get_selectable_fd");
    funcMap.put("pcap_getevent", "pcap_getevent");

    NATIVE_LOAD_LIBRARY_OPTIONS.put(
        Library.OPTION_FUNCTION_MAPPER,
        new FunctionMapper() {
          @Override
          public String getFunctionName(NativeLibrary library, Method method) {
            return funcMap.get(method.getName());
          }
        });
    PLATFORM_DEPENDENT = new DefaultPlatformDependent();
    isWinPcap = NativeMappings.pcap_lib_version().toLowerCase().contains("winpcap");

    AF_INET = 2;
    AF_INET6 = defaultAfInet6();
  }

  private NativeMappings() {}

  static String libName(boolean isWindows) {
    if (isWindows) {
      return "wpcap";
    } else {
      return "pcap";
    }
  }

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

  static native Pointer pcap_geterr(Pointer p);

  static native int pcap_findalldevs(PointerByReference alldevsp, ErrorBuffer errbuf);

  static native void pcap_freealldevs(Pointer p);

  static native Pointer pcap_open_offline(String fname, ErrorBuffer errbuf);

  static native Pointer pcap_create(String device, ErrorBuffer errbuf);

  static native int pcap_set_snaplen(Pointer p, int snaplen);

  static native int pcap_set_promisc(Pointer p, int promisc);

  static native int pcap_set_timeout(Pointer p, int timeout);

  static native int pcap_set_buffer_size(Pointer p, int bufferSize);

  static native int pcap_activate(Pointer p);

  static native int pcap_loop(Pointer p, int cnt, pcap_handler callback, Pointer user);

  static native int pcap_dispatch(Pointer p, int cnt, pcap_handler callback, Pointer user);

  static native int pcap_sendpacket(Pointer p, Pointer buf, int size);

  static native int pcap_compile(Pointer p, bpf_program fp, String str, int optimize, int netmask);

  static native int pcap_setfilter(Pointer p, bpf_program fp);

  static native void pcap_freecode(bpf_program fp);

  static native void pcap_close(Pointer p);

  static native void pcap_breakloop(Pointer p);

  static native int pcap_next_ex(Pointer p, PointerByReference h, PointerByReference data);

  static native Pointer pcap_dump_open(Pointer p, String fname);

  static native void pcap_dump(Pointer user, Pointer header, Pointer packet);

  static native int pcap_dump_flush(Pointer p);

  static native NativeLong pcap_dump_ftell(Pointer dumper);

  static native void pcap_dump_close(Pointer p);

  static native int pcap_stats(Pointer p, Pointer ps);

  static native int pcap_setdirection(Pointer p, int pcap_direction);

  static native int pcap_setnonblock(Pointer p, int nonblock, ErrorBuffer errbuf);

  static native int pcap_getnonblock(Pointer p, ErrorBuffer errbuf);

  static native int pcap_minor_version(Pointer p);

  static native int pcap_snapshot(Pointer p);

  static native int pcap_major_version(Pointer p);

  static native int pcap_is_swapped(Pointer p);

  static InetAddress inetAddress(sockaddr sockaddr) {
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

    void got_packet(Pointer args, Pointer header, Pointer packet);
  }

  interface PlatformDependent extends Library {

    int pcap_can_set_rfmon(Pointer p);

    String pcap_statustostr(int error);

    Pointer pcap_dump_open_append(Pointer p, String fname);

    int pcap_set_tstamp_type(Pointer p, int tstampType);

    int pcap_get_tstamp_precision(Pointer p);

    int pcap_set_rfmon(Pointer p, int rfmon);

    Pointer pcap_open_offline_with_tstamp_precision(
        String fname, int precision, ErrorBuffer errbuf);

    int pcap_set_tstamp_precision(Pointer p, int tstamp_precision);

    int pcap_set_immediate_mode(Pointer p, int immediate_mode);

    int pcap_get_selectable_fd(Pointer p);

    long pcap_getevent(Pointer p);
  }

  static class DefaultPlatformDependent implements PlatformDependent {

    private static final PlatformDependent NATIVE =
        com.sun.jna.Native.load(
            libName(Platform.isWindows()), PlatformDependent.class, NATIVE_LOAD_LIBRARY_OPTIONS);

    @Override
    public int pcap_can_set_rfmon(Pointer p) {
      try {
        return NATIVE.pcap_can_set_rfmon(p);
      } catch (NullPointerException | UnsatisfiedLinkError e) {
        System.err.println("pcap_can_set_frmon: Function doesn't exist.");
        return 0;
      }
    }

    @Override
    public String pcap_statustostr(int error) {
      try {
        return NATIVE.pcap_statustostr(error);
      } catch (NullPointerException | UnsatisfiedLinkError e) {
        return "pcap_statustostr: Function doesn't exist.";
      }
    }

    @Override
    public Pointer pcap_dump_open_append(Pointer p, String fname) {
      try {
        return NATIVE.pcap_dump_open_append(p, fname);
      } catch (NullPointerException | UnsatisfiedLinkError e) {
        System.err.println("pcap_dump_open_append: Function doesn't exist.");
        return null;
      }
    }

    @Override
    public int pcap_set_tstamp_type(Pointer p, int tstampType) {
      try {
        return NATIVE.pcap_set_tstamp_type(p, tstampType);
      } catch (NullPointerException | UnsatisfiedLinkError e) {
        System.err.println("pcap_set_tstamp_type: Function doesn't exist.");
        return 0;
      }
    }

    @Override
    public int pcap_get_tstamp_precision(Pointer p) {
      try {
        return NATIVE.pcap_get_tstamp_precision(p);
      } catch (NullPointerException | UnsatisfiedLinkError e) {
        System.err.println("pcap_get_tstamp_precision: Function doesn't exist.");
        return Timestamp.Precision.MICRO.value();
      }
    }

    @Override
    public int pcap_set_rfmon(Pointer p, int rfmon) {
      try {
        return NATIVE.pcap_set_rfmon(p, rfmon);
      } catch (NullPointerException | UnsatisfiedLinkError e) {
        System.err.println("pcap_set_rfmon: Function doesn't exist.");
        return 0;
      }
    }

    @Override
    public Pointer pcap_open_offline_with_tstamp_precision(
        String fname, int precision, ErrorBuffer errbuf) {
      try {
        return NATIVE.pcap_open_offline_with_tstamp_precision(fname, precision, errbuf);
      } catch (NullPointerException | UnsatisfiedLinkError e) {
        System.err.println("pcap_open_offline_with_tstamp_precision: Function doesn't exist.");
        return null;
      }
    }

    @Override
    public int pcap_set_tstamp_precision(Pointer p, int tstamp_precision) {
      try {
        return NATIVE.pcap_set_tstamp_precision(p, tstamp_precision);
      } catch (NullPointerException | UnsatisfiedLinkError e) {
        System.err.println("pcap_set_tstamp_precision: Function doesn't exist.");
        return 0;
      }
    }

    @Override
    public int pcap_set_immediate_mode(Pointer p, int immediate_mode) {
      try {
        return NATIVE.pcap_set_immediate_mode(p, immediate_mode);
      } catch (NullPointerException | UnsatisfiedLinkError e) {
        System.err.println("pcap_set_immediate_mode: Function doesn't exist.");
        return 0;
      }
    }

    @Override
    public int pcap_get_selectable_fd(Pointer p) {
      try {
        return NATIVE.pcap_get_selectable_fd(p);
      } catch (NullPointerException | UnsatisfiedLinkError e) {
        System.err.println("pcap_get_selectable_fd: Function doesn't exist.");
        return -1;
      }
    }

    @Override
    public long pcap_getevent(Pointer p) {
      try {
        return NATIVE.pcap_getevent(p);
      } catch (NullPointerException | UnsatisfiedLinkError e) {
        System.err.println("pcap_getevent: Function doesn't exist.");
        return -1;
      }
    }
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

    public bpf_program() {}

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

    public bpf_insn() {}

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

  public static class sockaddr extends Structure {

    private static final ByteOrder NATIVE_BYTE_ORDER = ByteOrder.nativeOrder();

    public short sa_family;
    public byte[] sa_data = new byte[14];

    public sockaddr() {}

    static boolean isLinuxOrWindows() {
      return Platform.isWindows() || Platform.isLinux();
    }

    static short getSaFamilyByByteOrder(short saFamily, ByteOrder bo) {
      if (bo.equals(ByteOrder.BIG_ENDIAN)) {
        return (short) (0xFF & saFamily);
      } else {
        return (short) (0xFF & (saFamily >> 8));
      }
    }

    @Override
    protected List<String> getFieldOrder() {
      List<String> fieldOrder = new ArrayList<String>();
      fieldOrder.add("sa_family");
      fieldOrder.add("sa_data");
      return fieldOrder;
    }

    public short getSaFamily() {
      if (isLinuxOrWindows()) {
        return sa_family;
      } else {
        return getSaFamilyByByteOrder(sa_family, NATIVE_BYTE_ORDER);
      }
    }

    public static class ByReference extends sockaddr implements Structure.ByReference {}
  }

  public static class pcap_if extends Structure implements Interface {

    public ByReference next;
    public String name;
    public String description;
    public pcap_addr.ByReference addresses;
    public int flags;

    public pcap_if() {}

    public pcap_if(Pointer pointer) {
      super(pointer);
      read();
    }

    @Override
    public pcap_if next() {
      return next;
    }

    @Override
    public String name() {
      return name;
    }

    @Override
    public String description() {
      return description;
    }

    @Override
    public pcap_addr addresses() {
      return addresses;
    }

    @Override
    public int flags() {
      return flags;
    }

    @Override
    public Iterator<Interface> iterator() {
      return new DefaultInterfaceIterator(this);
    }

    @Override
    protected List<String> getFieldOrder() {
      List<String> fieldOrder = new ArrayList<String>();
      fieldOrder.add("next");
      fieldOrder.add("name");
      fieldOrder.add("description");
      fieldOrder.add("addresses");
      fieldOrder.add("flags");
      return fieldOrder;
    }

    public static class ByReference extends pcap_if implements Structure.ByReference {}
  }

  public static class pcap_addr extends Structure implements Address {

    public ByReference next;
    public sockaddr.ByReference addr;
    public sockaddr.ByReference netmask;
    public sockaddr.ByReference broadaddr;
    public sockaddr.ByReference dstaddr;

    public pcap_addr() {}

    @Override
    public pcap_addr next() {
      return next;
    }

    @Override
    public InetAddress address() {
      return NativeMappings.inetAddress(addr);
    }

    @Override
    public InetAddress netmask() {
      return NativeMappings.inetAddress(netmask);
    }

    @Override
    public InetAddress broadcast() {
      return NativeMappings.inetAddress(broadaddr);
    }

    @Override
    public InetAddress destination() {
      return NativeMappings.inetAddress(dstaddr);
    }

    @Override
    public Iterator<Address> iterator() {
      return new DefaultAddressIterator(this);
    }

    @Override
    protected List<String> getFieldOrder() {
      List<String> fieldOrder = new ArrayList<String>();
      fieldOrder.add("next");
      fieldOrder.add("addr");
      fieldOrder.add("netmask");
      fieldOrder.add("broadaddr");
      fieldOrder.add("dstaddr");
      return fieldOrder;
    }

    public static class ByReference extends pcap_addr implements Structure.ByReference {}
  }
}
