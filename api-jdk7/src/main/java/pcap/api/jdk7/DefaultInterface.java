package pcap.api.jdk7;

import com.sun.jna.Pointer;
import com.sun.jna.Structure;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import pcap.spi.Interface;

public class DefaultInterface extends Structure implements Interface {

  public DefaultInterface.ByReference next;
  public String name;
  public String description;
  public DefaultAddress.ByReference addresses;
  public int flags;

  public DefaultInterface() {}

  public DefaultInterface(Pointer pointer) {
    super(pointer);
    read();
  }

  @Override
  public DefaultInterface next() {
    return next;
  }

  @Override
  public String name() {
    return name;
  }

  @Override
  public String description() {
    return description;
  }

  @Override
  public DefaultAddress addresses() {
    return addresses;
  }

  @Override
  public int flags() {
    return flags;
  }

  @Override
  public Iterator<Interface> iterator() {
    return new DefaultInterfaceIterator(this);
  }

  @Override
  protected List<String> getFieldOrder() {
    List<String> fieldOrder = new ArrayList<String>();
    fieldOrder.add("next");
    fieldOrder.add("name");
    fieldOrder.add("description");
    fieldOrder.add("addresses");
    fieldOrder.add("flags");
    return fieldOrder;
  }

  public static class ByReference extends DefaultInterface implements Structure.ByReference {}
}
