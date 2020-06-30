/** This code is licenced under the GPL version 2. */
package pcap.api.internal;

import java.foreign.NativeTypes;
import java.foreign.memory.Array;
import java.foreign.memory.LayoutType;
import java.foreign.memory.Pointer;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Iterator;
import pcap.api.internal.foreign.pcap_mapping;
import pcap.api.internal.foreign.struct.darwin_structs;
import pcap.api.internal.foreign.struct.linux_structs;
import pcap.api.internal.foreign.struct.windows_struct;
import pcap.api.internal.foreign.struct_mapping;
import pcap.api.internal.util.PcapAddressIterator;
import pcap.common.annotation.Inclubating;
import pcap.common.logging.Logger;
import pcap.common.logging.LoggerFactory;
import pcap.common.util.Bytes;
import pcap.common.util.Platforms;
import pcap.common.util.Strings;
import pcap.spi.Address;

/**
 * {@code Pcap} {@link Address} implementation
 *
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 */
@Inclubating
public class PcapAddress implements Address {

  private static final Logger LOGGER = LoggerFactory.getLogger(PcapAddress.class);

  Address next;
  InetAddress address;
  InetAddress netmask;
  InetAddress broadcast;
  InetAddress destination;

  PcapAddress(pcap_mapping.pcap_addr pcap_addr) {
    this.address = parse(pcap_addr.addr$get());
    this.netmask = parse(pcap_addr.netmask$get());
    this.broadcast = parse(pcap_addr.broadaddr$get());
    this.destination = parse(pcap_addr.dstaddr$get());
    if (!pcap_addr.next$get().isNull()) {
      this.next = new PcapAddress(pcap_addr.next$get().get());
    }
  }

  public Address next() {
    return next;
  }

  public InetAddress address() {
    return address;
  }

  public InetAddress netmask() {
    return netmask;
  }

  public InetAddress broadcast() {
    return broadcast;
  }

  public InetAddress destination() {
    return destination;
  }

  @Override
  public Iterator<Address> iterator() {
    return new PcapAddressIterator(this);
  }

  @Override
  public String toString() {
    return Strings.toStringBuilder(this)
        .add("address", address())
        .add("netmask", netmask())
        .add("broadcast", broadcast())
        .add("destination", destination())
        .toString();
  }

  private InetAddress parse(Pointer<struct_mapping.sockaddr> pointer) {
    if (!pointer.isNull()) {
      try {
        InetAddress inetAddress = null;
        if (Platforms.isLinux()) {
          linux_structs.sockaddr sockaddr =
              pointer
                  .cast(NativeTypes.VOID)
                  .cast(LayoutType.ofStruct(linux_structs.sockaddr.class))
                  .get();
          int sa_familty = sockaddr.sa_family$get();
          if (sa_familty == 2) {
            linux_structs.sockaddr_in sockaddr_in =
                pointer
                    .cast(NativeTypes.VOID)
                    .cast(LayoutType.ofStruct(linux_structs.sockaddr_in.class))
                    .get();
            inetAddress =
                Inet4Address.getByAddress(
                    Bytes.toByteArray(sockaddr_in.sin_addr$get().s_addr$get()));
          } else if (sa_familty == 10) {
            linux_structs.sockaddr_in6 sockaddr_in6 =
                pointer
                    .cast(NativeTypes.VOID)
                    .cast(LayoutType.ofStruct(linux_structs.sockaddr_in6.class))
                    .get();
            Array<Byte> byteArray = sockaddr_in6.sin6_addr$get().__in6_u$get().__u6_addr8$get();
            byte[] data = new byte[(int) byteArray.bytesSize()];
            for (int i = 0; i < data.length; i++) {
              data[i] = byteArray.get(i);
            }
            inetAddress = Inet6Address.getByAddress(data);
          }
        } else if (Platforms.isDarwin()) {
          darwin_structs.sockaddr sockaddr =
              pointer
                  .cast(NativeTypes.VOID)
                  .cast(LayoutType.ofStruct(darwin_structs.sockaddr.class))
                  .get();
          int sa_family = sockaddr.sa_family$get();
          if (sa_family == 2) {
            darwin_structs.sockaddr_in sockaddr_in =
                pointer
                    .cast(NativeTypes.VOID)
                    .cast(LayoutType.ofStruct(darwin_structs.sockaddr_in.class))
                    .get();
            inetAddress =
                Inet4Address.getByAddress(
                    Bytes.toByteArray(sockaddr_in.sin_addr$get().s_addr$get()));
          } else if (sa_family == 30) {
            darwin_structs.sockaddr_in6 sockaddr_in6 =
                pointer
                    .cast(NativeTypes.VOID)
                    .cast(LayoutType.ofStruct(darwin_structs.sockaddr_in6.class))
                    .get();
            final Array<Byte> byteArray =
                sockaddr_in6.sin6_addr$get().__u6_addr$get().__u6_addr8$get();
            if (byteArray.bytesSize() == 16) {
              byte[] data = new byte[16];
              for (int i = 0; i < data.length; i++) {
                data[i] = byteArray.get(i);
              }
              inetAddress = Inet6Address.getByAddress(data);
            }
          }
        } else if (Platforms.isWindows()) {
          windows_struct.sockaddr sockaddr =
              pointer
                  .cast(NativeTypes.VOID)
                  .cast(LayoutType.ofStruct(windows_struct.sockaddr.class))
                  .get();
          int sa_family = sockaddr.sa_family$get();
          if (sa_family == 2) {
            windows_struct.sockaddr_in sockaddr_in =
                pointer
                    .cast(NativeTypes.VOID)
                    .cast(LayoutType.ofStruct(windows_struct.sockaddr_in.class))
                    .get();
            windows_struct.anon$S_un_b b = sockaddr_in.sin_addr$get().S_un$get().S_un_b$get();
            inetAddress =
                Inet4Address.getByAddress(
                    new byte[] {b.s_b1$get(), b.s_b2$get(), b.s_b3$get(), b.s_b3$get()});
          } else if (sa_family == 23) {
            windows_struct.sockaddr_in6 sockaddr_in6 =
                pointer
                    .cast(NativeTypes.VOID)
                    .cast(LayoutType.ofStruct(windows_struct.sockaddr_in6.class))
                    .get();
            Array<Byte> byteArray = sockaddr_in6.sin6_addr$get().u$get().Byte$get();
            if (byteArray.bytesSize() == 16) {
              byte[] data = new byte[16];
              for (int i = 0; i < data.length; i++) {
                data[i] = byteArray.get(i);
              }
              inetAddress = Inet6Address.getByAddress(data);
            }
          }
        }
        return inetAddress;
      } catch (UnknownHostException e) {
        LOGGER.error("{}", e.getMessage());
      }
    }
    return null;
  }
}
