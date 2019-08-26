/**
 * This code is licenced under the GPL version 2.
 */
package pcap.common.util;

import java.io.Serializable;
import java.util.Set;

/**
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 */
public class MultipleNumber<K extends Number> extends MultipleObject<K> implements Serializable {

    private static final long serialVersionUID = -7486266343955776290L;

    private MultipleNumber(Set<K> keys) {
        super(keys);
    }

}
