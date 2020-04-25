package pcap.tools.commons.validator.impl;

import java.io.File;
import java.util.Iterator;
import javax.validation.ConstraintValidator;
import javax.validation.ConstraintValidatorContext;
import pcap.api.Pcaps;
import pcap.spi.Interface;
import pcap.spi.exception.ErrorException;
import pcap.tools.commons.SourceType;
import pcap.tools.commons.validator.Source;

public class SourceValidator implements ConstraintValidator<Source, Object> {

  private SourceType type;

  @Override
  public void initialize(Source constraintAnnotation) {
    type = constraintAnnotation.type();
  }

  @Override
  public boolean isValid(Object value, ConstraintValidatorContext context) {
    if (type == SourceType.NETWORK_INTERFACE) {
      if (value instanceof Interface) {
        try {
          Iterator<Interface> iterator = Pcaps.lookupInterface().iterator();
          while (iterator.hasNext()) {
            Interface source = (Interface) value;
            if (source.name().equals(iterator.next().name())) {
              return true;
            }
          }
        } catch (ErrorException e) {
          //
        }
      }
    } else if (type == SourceType.PCAP_FILE) {
      if (value instanceof File) {
        File source = (File) value;
        return source.exists();
      }
    }
    return false;
  }
}
