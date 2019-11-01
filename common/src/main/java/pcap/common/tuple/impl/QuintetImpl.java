/** This code is licenced under the GPL version 2. */
package pcap.common.tuple.impl;

import pcap.common.annotation.Inclubating;
import pcap.common.tuple.Quintet;
import pcap.common.tuple.Tuple;

/**
 * Implementations of quintet tuple.
 *
 * @param <L> left.
 * @param <BLM> between left and middle.
 * @param <M> middle,
 * @param <BRM> between right and middle.
 * @param <R> right.
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 */
@Inclubating
public class QuintetImpl<L, BLM, M, BRM, R> extends Tuple implements Quintet<L, BLM, M, BRM, R> {

  private final L left;
  private final BLM betweenLeftAndMiddle;
  private final M middle;
  private final BRM betweenRightAndMiddle;
  private final R right;

  public QuintetImpl(
      L left, BLM betweenLeftAndMiddle, M middle, BRM betweenRightAndMiddle, R right) {
    this.left = left;
    this.betweenLeftAndMiddle = betweenLeftAndMiddle;
    this.middle = middle;
    this.betweenRightAndMiddle = betweenRightAndMiddle;
    this.right = right;
  }

  @Override
  public L left() {
    return left;
  }

  @Override
  public BLM betweenLeftAndMiddle() {
    return betweenLeftAndMiddle;
  }

  @Override
  public M middle() {
    return middle;
  }

  @Override
  public BRM betweenRigthAndMiddle() {
    return betweenRightAndMiddle;
  }

  @Override
  public R right() {
    return right;
  }

  @Override
  public int size() {
    return 5;
  }

  @Override
  public String toString() {
    final StringBuilder sb = new StringBuilder("QuintetImpl{");
    sb.append("left=").append(left);
    sb.append(", betweenLeftAndMiddle=").append(betweenLeftAndMiddle);
    sb.append(", middle=").append(middle);
    sb.append(", betweenRightAndMiddle=").append(betweenRightAndMiddle);
    sb.append(", right=").append(right);
    sb.append('}');
    return sb.toString();
  }
}
