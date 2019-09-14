/** This code is licenced under the GPL version 2. */
package pcap.spi;

import java.net.InetAddress;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
public interface Address extends Iterable<Address> {

  Address next();

  InetAddress address();

  InetAddress netmask();

  InetAddress broadcast();

  InetAddress destination();
}
