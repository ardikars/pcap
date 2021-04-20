package pcap.spi;

import pcap.spi.annotation.Incubating;

/**
 * Selection key.
 *
 * @since 1.3.0 (incubating)
 */
@Incubating
public interface Selection {

  /**
   * Indicate the {@link Selectable} is ready to perform I/O read operation.
   *
   * @return returns {@code true} if ready to perform I/O read operation, {@code false} otherwise.
   * @since 1.3.0 (incubating)
   */
  @Incubating
  boolean isReadable();

  /**
   * Indicate the {@link Selectable} is ready to perform I/O write operation.
   *
   * @return returns {@code true} if ready to perform I/O write operation, {@code false} otherwise.
   * @since 1.3.0 (incubating)
   */
  @Incubating
  boolean isWriteable();

  /**
   * Set the interest I/O {@link Operation} for next {@link Selector#select(Timeout)}.
   *
   * @param operation operation.
   * @return returns this instance.
   * @since 1.3.0 (incubating)
   */
  @Incubating
  Selection interestOperation(Operation operation);

  /**
   * Interest operation.
   *
   * @since 1.3.0 (incubating)
   */
  @Incubating
  enum Operation {
    READ,
    WRITE
  }
}
