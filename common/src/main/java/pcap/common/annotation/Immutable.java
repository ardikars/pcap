/** This code is licenced under the GPL version 2. */
package pcap.common.annotation;

import java.lang.annotation.*;

/**
 * Annotate immutable object.
 *
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 * @since 1.0.0
 */
@Documented
@Inclubating
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.TYPE)
public @interface Immutable {

  /**
   * Mark field(s) as volatile.
   *
   * @return returns array of volatile field on specified class.
   * @since 1.0.0
   */
  String[] volatiles() default {};

  /**
   * Mark un-immutable fields.
   *
   * @return returns array of un-immutable field on specified class.
   * @since 1.0.0
   */
  String[] except() default {};

  /**
   * Blocking when changing specify field.
   *
   * @return returns true if blocking, false otherwise.
   * @since 1.0.0
   */
  boolean blocking() default false;
}
