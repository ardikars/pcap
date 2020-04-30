package pcap.api.internal;

import org.junit.Test;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.runner.RunWith;
import pcap.api.Pcaps;
import pcap.common.logging.Logger;
import pcap.common.logging.LoggerFactory;
import pcap.common.util.Objects;
import pcap.spi.Address;
import pcap.spi.Interface;
import pcap.spi.exception.ErrorException;

@RunWith(JUnitPlatform.class)
public class PcapAddressTest {

  private static final Logger LOGGER = LoggerFactory.getLogger(PcapAddressTest.class);

  @Test
  public void loop() throws ErrorException {
    for (Interface iface : Pcaps.lookupInterfaces()) {
      LOGGER.info(iface.name());
      LOGGER.info(iface.description());
      LOGGER.info(String.valueOf(iface.flags()));
      LOGGER.info(Objects.nonNull(iface.addresses()) ? iface.addresses().toString() : "");
      for (Address address : iface.addresses()) {
        LOGGER.info("\t{}", address.address());
        LOGGER.info("\t{}", address.netmask());
        LOGGER.info("\t{}", address.broadcast());
        LOGGER.info("\t{}", address.destination());
      }
    }
  }
}
