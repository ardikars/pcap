/** This code is licenced under the GPL version 2. */
package pcap.common.tuple;

import pcap.common.annotation.Inclubating;

/**
 * Quintet tuple.
 *
 * @param <L> left.
 * @param <BLM> between left and middle.
 * @param <M> middle,
 * @param <BRM> between right and middle.
 * @param <R> right.
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 */
@Inclubating
public interface Quintet<L, BLM, M, BRM, R> {

  L getLeft();

  BLM getBetweenLeftAndMiddle();

  M getMiddle();

  BRM getBetweenRigthAndMiddle();

  R getRight();
}
