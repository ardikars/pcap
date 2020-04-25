package pcap.tools.commons.validator;

import static java.lang.annotation.ElementType.PARAMETER;
import static java.lang.annotation.RetentionPolicy.RUNTIME;

import java.lang.annotation.Documented;
import java.lang.annotation.Retention;
import java.lang.annotation.Target;
import javax.validation.Constraint;
import javax.validation.Payload;
import pcap.tools.commons.SourceType;
import pcap.tools.commons.validator.impl.SourceValidator;

@Target({PARAMETER})
@Retention(RUNTIME)
@Constraint(validatedBy = SourceValidator.class)
@Documented
public @interface Source {

  SourceType type() default SourceType.NETWORK_INTERFACE;

  String message() default "Interface not found.";

  Class<?>[] groups() default {};

  Class<? extends Payload>[] payload() default {};
}
