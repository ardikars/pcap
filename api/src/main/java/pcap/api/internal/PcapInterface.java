/** This code is licenced under the GPL version 2. */
package pcap.api.internal;

import java.foreign.memory.Pointer;
import java.util.Iterator;
import pcap.api.internal.foreign.pcap_header;
import pcap.api.internal.util.PcapInterfaceIterator;
import pcap.common.annotation.Inclubating;
import pcap.common.util.Strings;
import pcap.spi.Address;
import pcap.spi.Interface;

/**
 * {@code Pcap} {@link Interface} implementation
 *
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 */
@Inclubating
public class PcapInterface implements Interface {

  Interface next;
  String name;
  String description;
  Address addresses;
  int flags;

  public PcapInterface(pcap_header.pcap_if pcap_if) {
    this.name = Pointer.toString(pcap_if.name$get());
    this.description = Pointer.toString(pcap_if.description$get());
    this.flags = pcap_if.flags$get();
    if (!pcap_if.addresses$get().isNull()) {
      this.addresses = new PcapAddress(pcap_if.addresses$get().get());
    }
    if (!pcap_if.next$get().isNull()) {
      this.next = new PcapInterface(pcap_if.next$get().get());
    }
  }

  @Override
  public Interface next() {
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
  public Address addresses() {
    return addresses;
  }

  public int flags() {
    return flags;
  }

  /**
   * Interface is "loopback".
   *
   * @return returns {@code true} if interface if "loopback", {@code false} otherwise.
   */
  public boolean isLoopback() {
    return (flags & 0x00000001) != 0;
  }

  /**
   * Interface is up.
   *
   * @return returns {@code true} if interface is up, {@code false} otherwise.
   */
  public boolean isUp() {
    return (flags & 0x00000002) != 0;
  }

  /**
   * Interface is running.
   *
   * @return returns {@code true} if interface is running, {@code false} otherwise.
   */
  public boolean isRunning() {
    return (flags & 0x00000004) != 0;
  }

  /**
   * interface is wireless (*NOT* necessarily Wi-Fi!)
   *
   * @return returns {@code true} if interface is wireless, {@code false}.
   */
  public boolean isWireless() {
    return (flags & 0x00000008) != 0;
  }

  /**
   * Connected.
   *
   * @return returns {@code true} if interface is connected to the network, {@code false}.
   */
  public boolean isConnected() {
    return (flags & 0x00000030) != 0 && (flags & 0x00000010) != 0;
  }

  /**
   * Disconnected.
   *
   * @return returns {@code true} if interface is disconnected from the network, {@code false}.
   */
  public boolean isDisconnected() {
    return (flags & 0x00000030) != 0 && (flags & 0x00000020) != 0;
  }

  @Override
  public Iterator<Interface> iterator() {
    return new PcapInterfaceIterator(this);
  }

  @Override
  public String toString() {
    return Strings.toStringBuilder(this)
        .add("name", name)
        .add("description", description)
        .add("flags", flags)
        .add("loopback", isLoopback())
        .add("up", isUp())
        .add("running", isRunning())
        .add("addresses", addresses)
        .toString();
  }
}
