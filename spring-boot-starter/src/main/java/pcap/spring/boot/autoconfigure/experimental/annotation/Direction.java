package pcap.spring.boot.autoconfigure.experimental.annotation;

import java.lang.annotation.*;
import pcap.common.annotation.Inclubating;
import pcap.spi.Pcap;

@Documented
@Inclubating
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.METHOD)
public @interface Direction {

  Pcap.Direction value();
}
