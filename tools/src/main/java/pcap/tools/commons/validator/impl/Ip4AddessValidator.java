package pcap.tools.commons.validator.impl;

import javax.validation.ConstraintValidator;
import javax.validation.ConstraintValidatorContext;
import pcap.common.net.Inet4Address;
import pcap.tools.commons.validator.Ip4Address;

public class Ip4AddessValidator implements ConstraintValidator<Ip4Address, String> {

  @Override
  public void initialize(Ip4Address ip4Address) {}

  @Override
  public boolean isValid(String value, ConstraintValidatorContext context) {
    return Inet4Address.isValidAddress(value);
  }
}
