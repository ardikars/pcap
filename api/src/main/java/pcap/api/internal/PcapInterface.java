/** This code is licenced under the GPL version 2. */
package pcap.api.internal;

import java.foreign.memory.Pointer;
import java.util.Iterator;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;
import pcap.api.internal.foreign.pcap_mapping;
import pcap.api.internal.util.PcapInterfaceIterator;
import pcap.common.annotation.Inclubating;
import pcap.common.logging.Logger;
import pcap.common.logging.LoggerFactory;
import pcap.spi.Address;
import pcap.spi.Interface;

/**
 * {@code Pcap} {@link Interface} implementation
 *
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 */
@Inclubating
public class PcapInterface implements Interface {

  private static final Logger LOGGER = LoggerFactory.getLogger(PcapInterface.class);

  /** Interface is loopback. */
  private static final int PCAP_IF_LOOPBACK = 0x00000001;

  /** Interface is up. */
  private static final int PCAP_IF_UP = 0x00000002;

  /** Interface is running. */
  private static final int PCAP_IF_RUNNING = 0x00000004;

  Interface next;
  String name;
  String description;
  Address addresses;
  int flags;
  boolean loopback;
  boolean up;
  boolean running;

  public PcapInterface(pcap_mapping.pcap_if pcap_if) {
    this.name = Pointer.toString(pcap_if.name$get());
    this.description = Pointer.toString(pcap_if.description$get());
    this.flags = pcap_if.flags$get();
    this.addresses = new PcapAddress(pcap_if.addresses$get().get());
    if (!pcap_if.next$get().isNull()) {
      this.next = new PcapInterface(pcap_if.next$get().get());
    }
    this.loopback = (this.flags & PCAP_IF_LOOPBACK) != 0;
    this.up = (this.flags & PCAP_IF_UP) != 0;
    this.running = (this.flags & PCAP_IF_RUNNING) != 0;
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
   * Is loopback interface?
   *
   * @return true if loopback interface, false otherwise.
   */
  public boolean isLoopback() {
    return loopback;
  }

  /**
   * Is interface is up?
   *
   * @return true if interface is up, false otherwise.
   */
  public boolean isUp() {
    return up;
  }

  /**
   * Is interface is running?
   *
   * @return true if interface is running, false otherwise.
   */
  public boolean isRunning() {
    return running;
  }

  @Override
  public Iterator<Interface> iterator() {
    return new PcapInterfaceIterator(this);
  }

  @Override
  public String toString() {
    StringBuilder sb =
        new StringBuilder()
            .append("{\n")
            .append("\t\"name\": \"")
            .append(name)
            .append("\",\n")
            .append("\t\"description\": \"")
            .append(description)
            .append("\",\n")
            .append("\t\"flags\": \"")
            .append(flags)
            .append("\",\n")
            .append("\t\"isLoopback\": \"")
            .append(isLoopback())
            .append("\",\n")
            .append("\t\"isUp\": \"")
            .append(isUp())
            .append("\",\n")
            .append("\t\"isRunning\": \"")
            .append(isRunning())
            .append("\",\n")
            .append("\t\"addresses\": \n")
            .append("\t\t[\n")
            .append(
                StreamSupport.stream(addresses.spliterator(), false)
                    .map(
                        addr ->
                            new StringBuilder()
                                .append("\t\t\t{\n")
                                .append("\t\t\t\t\"address\": \"")
                                .append(addr.address())
                                .append("\",\n")
                                .append("\t\t\t\t\"netmask\": \"")
                                .append(addr.netmask())
                                .append("\",\n")
                                .append("\t\t\t\t\"broadcast\": \"")
                                .append(addr.broadcast())
                                .append("\",\n")
                                .append("\t\t\t\t\"destination\": \"")
                                .append(addr.destination())
                                .append("\"\n")
                                .append("\t\t\t}")
                                .toString())
                    .collect(Collectors.joining(",\n")))
            .append("\n\t\t]\n")
            .append("}");
    return sb.toString();
  }
}
