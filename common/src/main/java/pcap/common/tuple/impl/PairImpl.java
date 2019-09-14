/** This code is licenced under the GPL version 2. */
package pcap.common.tuple.impl;

import pcap.common.annotation.Inclubating;
import pcap.common.tuple.Pair;
import pcap.common.tuple.Tuple;

/**
 * Implementation of pair tuple.
 *
 * @param <L> left.
 * @param <R> right.
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 */
@Inclubating
public class PairImpl<L, R> extends Tuple implements Pair<L, R> {

  private final L left;
  private final R right;

  public PairImpl(L left, R right) {
    this.left = left;
    this.right = right;
  }

  @Override
  public L getLeft() {
    return left;
  }

  @Override
  public R getRight() {
    return right;
  }

  @Override
  public int size() {
    return 2;
  }

  @Override
  public String toString() {
    final StringBuilder sb = new StringBuilder("PairImpl{");
    sb.append("left=").append(left);
    sb.append(", right=").append(right);
    sb.append('}');
    return sb.toString();
  }
}
