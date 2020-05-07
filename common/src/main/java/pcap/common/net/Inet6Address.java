/** This code is licenced under the GPL version 2. */
package pcap.common.net;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import pcap.common.annotation.Inclubating;
import pcap.common.util.Validate;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
@Inclubating
public final class Inet6Address extends InetAddress {

  /** Zero IPv6 Address. */
  public static final Inet6Address ZERO =
      valueOf(
          new byte[] {
            (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0,
            (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0,
            (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0,
            (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0,
          });

  /** IPv6 Loopback Address (::1). */
  public static final Inet6Address LOCALHOST = valueOf("::1");

  /** IPv6 Address Length. */
  public static final short IPV6_ADDRESS_LENGTH = 16;

  private byte[] address;

  {
    address = new byte[Inet6Address.IPV6_ADDRESS_LENGTH];
  }

  private Inet6Address() {}

  private Inet6Address(byte[] address) {
    Validate.nullPointer(address);
    Validate.notIllegalArgument(address.length == IPV6_ADDRESS_LENGTH);
    this.address = address;
  }

  /**
   * Determines the IPv6 address.
   *
   * @param bytesAddress ipv6 bytesAddress address.
   * @return an IPv6 address.
   */
  public static Inet6Address valueOf(final byte[] bytesAddress) {
    return new Inet6Address(bytesAddress);
  }

  /**
   * Determines the IPv6 address.
   *
   * @param stringAddress ipv6 stringAddress address.
   * @return an IPv6 address.
   */
  public static Inet6Address valueOf(String stringAddress) {

    stringAddress = Validate.nullPointerThenReturns(stringAddress, "::");

    final int ipv6MaxHexGroups = 8;
    final int ipv6MaxHexDigitsPerGroup = 4;

    boolean containsCompressedZeroes = stringAddress.contains("::");
    Validate.notIllegalArgument(
        !(containsCompressedZeroes
            && (stringAddress.indexOf("::") != stringAddress.lastIndexOf("::"))));
    Validate.notIllegalArgument(
        !((stringAddress.startsWith(":") && !stringAddress.startsWith("::"))
            || (stringAddress.endsWith(":") && !stringAddress.endsWith("::"))));
    String[] parts = stringAddress.split(":");
    if (containsCompressedZeroes) {
      List<String> partsAsList = new ArrayList<>(Arrays.asList(parts));
      if (stringAddress.endsWith("::")) {
        partsAsList.add("");
      } else if (stringAddress.startsWith("::") && !partsAsList.isEmpty()) {
        partsAsList.remove(0);
      }
      parts = partsAsList.toArray(new String[partsAsList.size()]);
    }
    Validate.notIllegalArgument(!(parts.length > ipv6MaxHexGroups));
    int validOctets = 0;
    int emptyOctets = 0;
    for (int index = 0; index < parts.length; index++) {
      String octet = parts[index];
      if (octet.length() == 0) {
        emptyOctets++;
        Validate.notIllegalArgument(!(emptyOctets > 1));
      } else {
        emptyOctets = 0;
        if (index == parts.length - 1 && octet.contains(".")) {
          byte[] quad;
          quad = Inet4Address.valueOf(octet).address();
          String initialPart = stringAddress.substring(0, stringAddress.lastIndexOf(":") + 1);
          String penultimate = Integer.toHexString(((quad[0] & 0xff) << 8) | (quad[1] & 0xff));
          String ultimate = Integer.toHexString(((quad[2] & 0xff) << 8) | (quad[3] & 0xff));
          stringAddress = initialPart + penultimate + ultimate;
          validOctets += 2;
          continue;
        }
        Validate.notIllegalArgument(!(octet.length() > ipv6MaxHexDigitsPerGroup));
      }
      validOctets++;
    }
    Validate.notIllegalArgument(
        !(validOctets > ipv6MaxHexGroups
            || (validOctets < ipv6MaxHexGroups && !containsCompressedZeroes)));
    parts = stringAddress.split(":", 8 + 2);
    Validate.notIllegalArgument(!(parts.length < 3 || parts.length > 8 + 1));
    int skipIndex = -1;
    for (int i = 1; i < parts.length - 1; i++) {
      if (parts[i].length() == 0) {
        Validate.notIllegalArgument(!(skipIndex >= 0));
        skipIndex = i;
      }
    }
    int partsHi;
    int partsLo;
    if (skipIndex >= 0) {
      partsHi = skipIndex;
      partsLo = parts.length - skipIndex - 1;
      Validate.notIllegalArgument(!(parts[0].length() == 0 && --partsHi != 0));
      Validate.notIllegalArgument(!(parts[parts.length - 1].length() == 0 && --partsLo != 0));
    } else {
      partsHi = parts.length;
      partsLo = 0;
    }
    int partsSkipped = 8 - (partsHi + partsLo);
    Validate.notIllegalArgument((skipIndex >= 0 ? partsSkipped >= 1 : partsSkipped == 0));
    ByteBuffer rawBytes = ByteBuffer.allocate(2 * 8);
    try {
      for (int i = 0; i < partsHi; i++) {
        rawBytes.putShort(parseHextet(parts[i]));
      }
      for (int i = 0; i < partsSkipped; i++) {
        rawBytes.putShort((short) 0);
      }
      for (int i = partsLo; i > 0; i--) {
        rawBytes.putShort(parseHextet(parts[parts.length - i]));
      }
    } catch (NumberFormatException ex) {
      return null;
    }
    return new Inet6Address(rawBytes.array());
  }

  @Override
  public boolean isMulticastAddress() {
    return ((address[0] & 0xff) == 0xff);
  }

  @Override
  public boolean isAnyLocalAddress() {
    byte test = 0x00;
    for (int i = 0; i < Inet6Address.IPV6_ADDRESS_LENGTH; i++) {
      test |= address[i];
    }
    return (test == 0x00);
  }

  @Override
  public boolean isLoopbackAddress() {
    byte test = 0x00;
    for (int i = 0; i < 15; i++) {
      test |= address[i];
    }
    return (test == 0x00) && (address[15] == 0x01);
  }

  @Override
  public boolean isLinkLocalAddress() {
    return ((address[0] & 0xff) == 0xfe && (address[1] & 0xc0) == 0x80);
  }

  @Override
  public boolean isSiteLocalAddress() {
    return ((address[0] & 0xff) == 0xfe && (address[1] & 0xc0) == 0xc0);
  }

  @Override
  public boolean isMcGlobal() {
    return ((address[0] & 0xff) == 0xff && (address[1] & 0x0f) == 0x0e);
  }

  @Override
  public boolean isMcNodeLocal() {
    return ((address[0] & 0xff) == 0xff && (address[1] & 0x0f) == 0x01);
  }

  @Override
  public boolean isMcLinkLocal() {
    return ((address[0] & 0xff) == 0xff && (address[1] & 0x0f) == 0x02);
  }

  @Override
  public boolean isMcSiteLocal() {
    return ((address[0] & 0xff) == 0xff && (address[1] & 0x0f) == 0x05);
  }

  @Override
  public boolean isMcOrgLocal() {
    return ((address[0] & 0xff) == 0xff && (address[1] & 0x0f) == 0x08);
  }

  /**
   * Returns {@code long} address.
   *
   * @return returns {@code long} address.
   */
  public long toLong() {
    ByteBuffer bb = ByteBuffer.allocate(this.address.length);
    bb.put(this.address);
    return bb.getLong();
  }

  private static short parseHextet(final String ipPart) {
    int hextet = Integer.parseInt(ipPart, 16);
    if (hextet > 0xffff) {
      throw new NumberFormatException();
    }
    return (short) hextet;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }

    Inet6Address that = (Inet6Address) o;

    return Arrays.equals(address, that.address);
  }

  @Override
  public int hashCode() {
    return Arrays.hashCode(address);
  }

  /**
   * returns ipv6 string.
   *
   * @return ipv6 string.
   */
  public String toString() {
    int cmprHextet = -1;
    int cmprSize = 0;
    for (int hextet = 0; hextet < 7; ) {
      int curByte = hextet * 2;
      int size = 0;
      while (curByte < this.address.length
          && this.address[curByte] == 0
          && this.address[curByte + 1] == 0) {
        curByte += 2;
        size++;
      }
      if (size > cmprSize) {
        cmprHextet = hextet;
        cmprSize = size;
      }
      hextet = (curByte / 2) + 1;
    }
    StringBuilder sb = new StringBuilder(39);
    if (cmprHextet == -1 || cmprSize < 2) {
      ipv6toStr(sb, this.address, 0, 8);
      return sb.toString();
    }
    ipv6toStr(sb, this.address, 0, cmprHextet);
    sb.append(new char[] {':', ':'});
    ipv6toStr(sb, this.address, cmprHextet + cmprSize, 8);
    return sb.toString();
  }

  private static void ipv6toStr(StringBuilder sb, byte[] src, int fromHextet, int toHextet) {
    for (int i = fromHextet; i < toHextet; i++) {
      sb.append(Integer.toHexString(((src[i << 1] << 8) & 0xff00) | (src[(i << 1) + 1] & 0xff)));
      if (i < toHextet - 1) {
        sb.append(':');
      }
    }
  }

  /**
   * Returns the raw IPv6 address of this {@code Inet6Address} object.
   *
   * @return the raw IPv6 address of this object.
   */
  @Override
  public byte[] address() {
    return Arrays.copyOf(this.address, this.address.length);
  }
}
