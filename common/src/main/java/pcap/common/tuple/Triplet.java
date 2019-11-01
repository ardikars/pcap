/** This code is licenced under the GPL version 2. */
package pcap.common.tuple;

import pcap.common.annotation.Inclubating;

/**
 * Triplet tuple
 *
 * @param <L> left.
 * @param <M> middle.
 * @param <R> right.
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 */
@Inclubating
public interface Triplet<L, M, R> {

  L left();

  M middle();

  R right();
}
