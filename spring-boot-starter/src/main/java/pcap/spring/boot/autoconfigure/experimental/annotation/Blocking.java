package pcap.spring.boot.autoconfigure.experimental.annotation;

import java.lang.annotation.*;
import pcap.common.annotation.Inclubating;

@Documented
@Inclubating
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.METHOD)
public @interface Blocking {

  boolean value() default true;
}
