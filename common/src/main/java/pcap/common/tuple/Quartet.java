/** This code is licenced under the GPL version 2. */
package pcap.common.tuple;

import pcap.common.annotation.Inclubating;

/**
 * Quertet tuple.
 *
 * @param <L> left.
 * @param <ML> middle left.
 * @param <MR> middle right.
 * @param <R> right.
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 */
@Inclubating
public interface Quartet<L, ML, MR, R> {

  L getLeft();

  ML getMiddleLeft();

  MR getMiddleRight();

  R getRight();
}
