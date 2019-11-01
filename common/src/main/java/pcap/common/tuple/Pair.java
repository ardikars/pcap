/** This code is licenced under the GPL version 2. */
package pcap.common.tuple;

import pcap.common.annotation.Inclubating;

/**
 * Pair tuple.
 *
 * @param <L> left.
 * @param <R> right.
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 */
@Inclubating
public interface Pair<L, R> {

  L left();

  R right();
}
