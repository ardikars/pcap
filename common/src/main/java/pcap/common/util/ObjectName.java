/**
 * This code is licenced under the GPL version 2.
 */
package pcap.common.util;

import java.io.Serializable;

/**
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 */
public interface ObjectName<T, U> extends Serializable {

    @Deprecated
    T getValue();

    String getName();

}
