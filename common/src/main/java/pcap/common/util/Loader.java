/**
 * This code is licenced under the GPL version 2.
 */
package pcap.common.util;

/**
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 */
public interface Loader<T> {

    void load(Callback<T> callback);

    void load(Callback<T> callback, Class[] loadClasses);

}
