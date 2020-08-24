/** This code is licenced under the GPL version 2. */
package pcap.common.util;

import java.io.Serializable;
import pcap.common.annotation.Inclubating;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
@Inclubating
public interface ObjectName extends Serializable {

  String name();
}
