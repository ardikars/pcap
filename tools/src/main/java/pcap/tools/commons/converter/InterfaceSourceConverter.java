package pcap.tools.commons.converter;

import java.util.Iterator;
import org.springframework.core.convert.converter.Converter;
import org.springframework.stereotype.Component;
import pcap.api.Pcaps;
import pcap.spi.Address;
import pcap.spi.Interface;
import pcap.spi.exception.ErrorException;

@Component
public class InterfaceSourceConverter implements Converter<String, Interface> {

  @Override
  public Interface convert(String source) {
    try {
      return Pcaps.lookupInterface(source);
    } catch (ErrorException e) {
      return new InvalidInterfaceSource(source);
    }
  }

  private static class InvalidInterfaceSource implements Interface {

    private final String name;

    public InvalidInterfaceSource(String name) {
      this.name = name;
    }

    @Override
    public Interface next() {
      return null;
    }

    @Override
    public String name() {
      return name;
    }

    @Override
    public String description() {
      return "Interface not found";
    }

    @Override
    public Address addresses() {
      return null;
    }

    @Override
    public int flags() {
      return 0;
    }

    @Override
    public Iterator<Interface> iterator() {
      return null;
    }

    @Override
    public String toString() {
      return name;
    }
  }
}
