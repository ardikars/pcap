/** This code is licenced under the GPL version 2. */
package pcap.common.tuple.impl;

import pcap.common.annotation.Inclubating;
import pcap.common.tuple.Quartet;
import pcap.common.tuple.Tuple;

/**
 * Implementations of quertet tuple.
 *
 * @param <L> left.
 * @param <ML> middle left.
 * @param <MR> middle right.
 * @param <R> right.
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 */
@Inclubating
public class QuartetImpl<L, ML, MR, R> extends Tuple implements Quartet<L, ML, MR, R> {

  private final L left;
  private final ML middleLeft;
  private final MR middleRight;
  private final R right;

  public QuartetImpl(L left, ML middleLeft, MR middleRight, R right) {
    this.left = left;
    this.middleLeft = middleLeft;
    this.middleRight = middleRight;
    this.right = right;
  }

  @Override
  public L getLeft() {
    return left;
  }

  @Override
  public ML getMiddleLeft() {
    return middleLeft;
  }

  @Override
  public MR getMiddleRight() {
    return middleRight;
  }

  @Override
  public R getRight() {
    return right;
  }

  @Override
  public int size() {
    return 4;
  }
}
