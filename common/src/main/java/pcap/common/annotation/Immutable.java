/** This code is licenced under the GPL version 2. */
package pcap.common.annotation;

import java.lang.annotation.*;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
@Documented
@Inclubating
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.TYPE)
public @interface Immutable {

  String[] volatiles() default {};

  String[] except() default {};

  boolean blocking() default false;
}
