package pcap.api.jdk7;

import com.sun.jna.Platform;
import com.sun.jna.Structure;
import java.net.InetAddress;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import pcap.spi.Address;

public class DefaultAddress extends Structure implements Address {

  public DefaultAddress.ByReference next;
  public sockaddr.ByReference addr;
  public sockaddr.ByReference netmask;
  public sockaddr.ByReference broadaddr;
  public sockaddr.ByReference dstaddr;

  public DefaultAddress() {}

  @Override
  public DefaultAddress next() {
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

  public static class ByReference extends DefaultAddress implements Structure.ByReference {}

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
}
