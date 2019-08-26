/**
 * This code is licenced under the GPL version 2.
 */
package pcap.common.util;

/**
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 */
public interface Callback<T> {

    void onSuccess(T value);

    void onFailure(Throwable throwable);

}
