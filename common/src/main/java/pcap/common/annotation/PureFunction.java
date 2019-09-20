package pcap.common.annotation;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Documented
@Inclubating
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.METHOD)
public @interface PureFunction {}
