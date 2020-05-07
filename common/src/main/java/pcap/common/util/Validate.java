/** This code is licenced under the GPL version 2. */
package pcap.common.util;

import pcap.common.annotation.Inclubating;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
@Inclubating
public final class Validate {

  private Validate() {
    //
  }

  /**
   * Ensures that given object ${@code reference} is not null.
   *
   * @param reference object reference.
   * @param message exceptions message to be given.
   * @param <T> object reference type.
   * @throws NullPointerException if {@code reference} is null.
   * @since 1.0.0
   */
  public static <T> void nullPointer(T reference, String message) throws NullPointerException {
    if (reference == null) {
      throw new NullPointerException(message);
    }
  }

  /**
   * Ensures that given object ${@code reference} is not null.
   *
   * @param reference object reference.
   * @param <T> object reference type.
   * @throws NullPointerException if {@code reference} is null.
   * @since 1.0.0
   */
  public static <T> void nullPointer(T reference) throws NullPointerException {
    nullPointer(reference, null);
  }

  /**
   * Ensures that given object ${@code reference} is not null.
   *
   * @param reference object reference.
   * @param newVal new value.
   * @param <T> object reference and new value type.
   * @return returns given ${@code newVal} if {@code reference} is null, {@code reference}
   *     otherwise.
   * @since 1.0.0
   */
  @SuppressWarnings("TypeParameterUnusedInFormals")
  public static <T> T nullPointerThenReturns(T reference, T newVal) {
    if (reference == null) {
      return newVal;
    } else {
      return reference;
    }
  }

  /**
   * Ensures the truth of an expression involving one or more parameters to the calling method.
   * Returns given ${@code newVal} if {@code expression} is false, {@code reference} otherwise.
   *
   * @param expression a boolean expression.
   * @param reference reference.
   * @param newVal new value.
   * @param <T> type of reference and new value.
   * @return returns given ${@code newVal} if {@code expression} is false, {@code reference}
   *     otherwise.
   * @since 1.0.0
   */
  @SuppressWarnings("TypeParameterUnusedInFormals")
  public static <T> T notIllegalArgumentThenReturns(boolean expression, T reference, T newVal) {
    if (!expression) {
      return newVal;
    } else {
      return reference;
    }
  }

  /**
   * Ensures the truth of an expression involving one or more parameters to the calling method.
   *
   * @param expression a boolean expression.
   * @param message exceptions message to be given
   * @throws IllegalArgumentException if {@code expression} is false
   * @since 1.0.0
   */
  public static void notIllegalArgument(boolean expression, String message)
      throws IllegalArgumentException {
    if (!expression) {
      throw new IllegalArgumentException(message);
    }
  }

  /**
   * Ensures the truth of an expression involving one or more parameters to the calling method.
   *
   * @param expression a boolean expression.
   * @throws IllegalArgumentException if {@code expression} is false
   * @since 1.0.0
   */
  public static void notIllegalArgument(boolean expression) throws IllegalArgumentException {
    notIllegalArgument(expression, null);
  }

  /**
   * Ensures the truth of an expression involving one or more parameters to the calling method.
   * Returns given ${@code newVal} if {@code expression} is false, {@code reference} otherwise.
   *
   * @param expression a boolean expression.
   * @param reference reference.
   * @param newVal new value.
   * @param <T> type of reference and new value.
   * @return returns given ${@code newVal} if {@code expression} is false, {@code reference}
   *     otherwise.
   * @since 1.0.0
   */
  @SuppressWarnings("TypeParameterUnusedInFormals")
  public static <T> T notIllegaStateThenReturns(boolean expression, T reference, T newVal) {
    if (!expression) {
      return newVal;
    } else {
      return reference;
    }
  }

  /**
   * Ensures the truth of an expression involving one or more parameters to the calling method.
   *
   * @param expression a boolean expression.
   * @param message exceptions message to be given
   * @throws IllegalStateException if {@code expression} is false
   * @since 1.0.0
   */
  public static void notIllegalState(boolean expression, String message)
      throws IllegalArgumentException {
    if (!expression) {
      throw new IllegalStateException(message);
    }
  }

  /**
   * Ensures the truth of an expression involving one or more parameters to the calling method.
   *
   * @param expression a boolean expression.
   * @throws IllegalStateException if {@code expression} is false
   * @since 1.0.0
   */
  public static void notIllegalState(boolean expression) throws IllegalStateException {
    notIllegalState(expression, null);
  }

  /**
   * Ensures that given parameter is valid bound in an array.
   *
   * @param array array.
   * @param offset offset.
   * @param length length.
   * @throws NullPointerException if {@code array} is null.
   * @throws IllegalArgumentException invalid parameters.
   * @throws ArrayIndexOutOfBoundsException invalid parameters.
   * @since 1.0.0
   */
  public static void notInBounds(byte[] array, int offset, int length)
      throws NullPointerException, IllegalArgumentException, ArrayIndexOutOfBoundsException {
    nullPointer(array, "array is null.");
    notIllegalArgument(array.length > 0, "array is empty.");
    notIllegalArgument(length > 0, "length is zero.");
    if (offset < 0
        || length < 0
        || length > array.length
        || offset > array.length - 1
        || offset + length > array.length) {
      throw new ArrayIndexOutOfBoundsException();
    }
  }

  /**
   * Ensures that given parameter is valid bound in an array.
   *
   * @param array array.
   * @param offset offset.
   * @param length length.
   * @throws NullPointerException if {@code array} is null.
   * @throws IllegalArgumentException invalid parameters.
   * @throws ArrayIndexOutOfBoundsException invalid parameters.
   * @since 1.0.0
   */
  public static void notInBounds(char[] array, int offset, int length)
      throws NullPointerException, IllegalArgumentException, ArrayIndexOutOfBoundsException {
    nullPointer(array, "array is null.");
    notIllegalArgument(array.length > 0, "array is empty.");
    notIllegalArgument(length > 0, "length is zero.");
    if (offset < 0
        || length < 0
        || length > array.length
        || offset > array.length - 1
        || offset + length > array.length) {
      throw new ArrayIndexOutOfBoundsException();
    }
  }

  /**
   * Ensures that given parameter is valid bound in an array.
   *
   * @param array array.
   * @param offset offset.
   * @param length length.
   * @throws NullPointerException if {@code array} is null.
   * @throws IllegalArgumentException invalid parameters.
   * @throws ArrayIndexOutOfBoundsException invalid parameters.
   * @since 1.0.0
   */
  public static void notInBounds(short[] array, int offset, int length)
      throws NullPointerException, IllegalArgumentException, ArrayIndexOutOfBoundsException {
    nullPointer(array, "array is null.");
    notIllegalArgument(array.length > 0, "array is empty.");
    notIllegalArgument(length > 0, "length is zero.");
    if (offset < 0
        || length < 0
        || length > array.length
        || offset > array.length - 1
        || offset + length > array.length) {
      throw new ArrayIndexOutOfBoundsException();
    }
  }

  /**
   * Ensures that given parameter is valid bound in an array.
   *
   * @param array array.
   * @param offset offset.
   * @param length length.
   * @throws NullPointerException if {@code array} is null.
   * @throws IllegalArgumentException invalid parameters.
   * @throws ArrayIndexOutOfBoundsException invalid parameters.
   * @since 1.0.0
   */
  public static void notInBounds(int[] array, int offset, int length)
      throws NullPointerException, IllegalArgumentException, ArrayIndexOutOfBoundsException {
    nullPointer(array, "array is null.");
    notIllegalArgument(array.length > 0, "array is empty.");
    notIllegalArgument(length > 0, "length is zero.");
    if (offset < 0
        || length < 0
        || length > array.length
        || offset > array.length - 1
        || offset + length > array.length) {
      throw new ArrayIndexOutOfBoundsException();
    }
  }

  /**
   * Ensures that given parameter is valid bound in an array.
   *
   * @param array array.
   * @param offset offset.
   * @param length length.
   * @throws NullPointerException if {@code array} is null.
   * @throws IllegalArgumentException invalid parameters.
   * @throws ArrayIndexOutOfBoundsException invalid parameters.
   * @since 1.0.0
   */
  public static void notInBounds(float[] array, int offset, int length)
      throws NullPointerException, IllegalArgumentException, ArrayIndexOutOfBoundsException {
    nullPointer(array, "array is null.");
    notIllegalArgument(array.length > 0, "array is empty.");
    notIllegalArgument(length > 0, "length is zero.");
    if (offset < 0
        || length < 0
        || length > array.length
        || offset > array.length - 1
        || offset + length > array.length) {
      throw new ArrayIndexOutOfBoundsException();
    }
  }

  /**
   * Ensures that given parameter is valid bound in an array.
   *
   * @param array array.
   * @param offset offset.
   * @param length length.
   * @throws NullPointerException if {@code array} is null.
   * @throws IllegalArgumentException invalid parameters.
   * @throws ArrayIndexOutOfBoundsException invalid parameters.
   * @since 1.0.0
   */
  public static void notInBounds(long[] array, int offset, int length)
      throws NullPointerException, IllegalArgumentException, ArrayIndexOutOfBoundsException {
    nullPointer(array, "array is null.");
    notIllegalArgument(array.length > 0, "array is empty.");
    notIllegalArgument(length > 0, "length is zero.");
    if (offset < 0
        || length < 0
        || length > array.length
        || offset > array.length - 1
        || offset + length > array.length) {
      throw new ArrayIndexOutOfBoundsException();
    }
  }

  /**
   * Ensures that given parameter is valid bound in an array.
   *
   * @param array array.
   * @param offset offset.
   * @param length length.
   * @throws NullPointerException if {@code array} is null.
   * @throws IllegalArgumentException invalid parameters.
   * @throws ArrayIndexOutOfBoundsException invalid parameters.
   * @since 1.0.0
   */
  public static void notInBounds(double[] array, int offset, int length)
      throws NullPointerException, IllegalArgumentException, ArrayIndexOutOfBoundsException {
    nullPointer(array, "array is null.");
    notIllegalArgument(array.length > 0, "array is empty.");
    notIllegalArgument(length > 0, "length is zero.");
    if (offset < 0
        || length < 0
        || length > array.length
        || offset > array.length - 1
        || offset + length > array.length) {
      throw new ArrayIndexOutOfBoundsException();
    }
  }

  /**
   * Ensures that given parameter is valid bound in an array.
   *
   * @param array array.
   * @param offset offset.
   * @param length length.
   * @param <T> array type.
   * @throws NullPointerException if {@code array} is null.
   * @throws IllegalArgumentException invalid parameters.
   * @throws ArrayIndexOutOfBoundsException invalid parameters.
   * @since 1.0.0
   */
  public static <T> void notInBounds(T[] array, int offset, int length)
      throws NullPointerException, IllegalArgumentException, ArrayIndexOutOfBoundsException {
    nullPointer(array, "array is null.");
    notIllegalArgument(array.length > 0, "array is empty.");
    notIllegalArgument(length > 0, "length is zero.");
    if (offset < 0
        || length < 0
        || length > array.length
        || offset > array.length - 1
        || offset + length > array.length) {
      throw new ArrayIndexOutOfBoundsException();
    }
  }

  /**
   * Ensures that given parameter is valid bound.
   *
   * @param size size.
   * @param offset offset.
   * @param length length.
   * @throws IllegalArgumentException illegal argement exception.
   * @since 1.1.0
   */
  public static void notInBounds(int size, int offset, int length) throws IllegalArgumentException {
    notIllegalArgument(size > 0, "size should be greater then zero.");
    notIllegalArgument(length > 0, "length is zero.");
    if (offset < 0 || length < 0 || length > size || offset > size - 1 || offset + length > size) {
      throw new ArrayIndexOutOfBoundsException();
    }
  }
}
