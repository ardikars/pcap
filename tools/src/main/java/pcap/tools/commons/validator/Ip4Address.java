package pcap.tools.commons.validator;

import static java.lang.annotation.ElementType.PARAMETER;
import static java.lang.annotation.RetentionPolicy.RUNTIME;

import java.lang.annotation.Documented;
import java.lang.annotation.Retention;
import java.lang.annotation.Target;
import javax.validation.Constraint;
import javax.validation.Payload;
import pcap.tools.commons.validator.impl.Ip4AddessValidator;

@Target({PARAMETER})
@Retention(RUNTIME)
@Constraint(validatedBy = Ip4AddessValidator.class)
@Documented
public @interface Ip4Address {

  String message() default "Invalid IPv4 address.";

  Class<?>[] groups() default {};

  Class<? extends Payload>[] payload() default {};
}
