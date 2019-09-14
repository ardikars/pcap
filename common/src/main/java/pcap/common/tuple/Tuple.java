/** This code is licenced under the GPL version 2. */
package pcap.common.tuple;

import java.io.Serializable;
import pcap.common.annotation.Inclubating;
import pcap.common.tuple.impl.PairImpl;
import pcap.common.tuple.impl.QuartetImpl;
import pcap.common.tuple.impl.QuintetImpl;
import pcap.common.tuple.impl.TripletImpl;

/**
 * Helper class for create tuple.
 *
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 */
@Inclubating
public abstract class Tuple implements Serializable {

  public abstract int size();

  public static <L, R> Pair<L, R> of(L left, R right) {
    return new PairImpl<L, R>(left, right);
  }

  public static <L, M, R> Triplet<L, M, R> of(L left, M middle, R right) {
    return new TripletImpl<L, M, R>(left, middle, right);
  }

  public static <L, ML, MR, R> Quartet<L, ML, MR, R> of(
      L left, ML middleLeft, MR middleRight, R right) {
    return new QuartetImpl<L, ML, MR, R>(left, middleLeft, middleRight, right);
  }

  public static <L, BLM, M, BRM, R> Quintet<L, BLM, M, BRM, R> of(
      L left, BLM betweenLeftAndMiddle, M middle, BRM betweenRightAndMiddle, R right) {
    return new QuintetImpl<L, BLM, M, BRM, R>(
        left, betweenLeftAndMiddle, middle, betweenRightAndMiddle, right);
  }
}
