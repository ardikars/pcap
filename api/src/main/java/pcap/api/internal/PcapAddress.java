/** This code is licenced under the GPL version 2. */
package pcap.api.internal;

import java.net.InetAddress;
import java.util.Iterator;
import pcap.api.internal.foreign.pcap_mapping;
import pcap.api.internal.util.PcapAddressIterator;
import pcap.api.internal.util.SockAddrParser;
import pcap.common.annotation.Inclubating;
import pcap.spi.Address;

/**
 * {@code Pcap} {@link Address} implementation
 *
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 */
@Inclubating
public class PcapAddress implements Address {

  Address next;
  InetAddress address;
  InetAddress netmask;
  InetAddress broadcast;
  InetAddress destination;

  PcapAddress(pcap_mapping.pcap_addr pcap_addr) {
    SockAddrParser parser = SockAddrParser.getInstance();
    this.address = parser.parse(pcap_addr.addr$get());
    this.netmask = parser.parse(pcap_addr.netmask$get());
    this.broadcast = parser.parse(pcap_addr.broadaddr$get());
    this.destination = parser.parse(pcap_addr.dstaddr$get());
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
    return new StringBuilder()
        .append("{\n")
        .append("\t\"address\": \"")
        .append(address)
        .append("\",\n")
        .append("\t\"netmask\": \"")
        .append(netmask)
        .append("\",\n")
        .append("\t\"broadcast\": \"")
        .append(broadcast)
        .append("\",\n")
        .append("\t\"destination\": \"")
        .append(destination)
        .append("\"\n")
        .append("}")
        .toString();
  }
}
