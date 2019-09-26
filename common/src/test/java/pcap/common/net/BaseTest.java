/** This code is licenced under the GPL version 2. */
package pcap.common.net;

import java.net.NetworkInterface;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.util.Enumeration;
import org.junit.jupiter.api.Test;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.runner.RunWith;

@RunWith(JUnitPlatform.class)
public class BaseTest {

  @Test
  public void init() throws SocketException, UnknownHostException {
    Enumeration<NetworkInterface> networkInterfaces = NetworkInterface.getNetworkInterfaces();
    while (networkInterfaces.hasMoreElements()) {
      NetworkInterface networkInterface = networkInterfaces.nextElement();
      Enumeration<NetworkInterface> subNetworkInterfaces = networkInterface.getSubInterfaces();
      while (subNetworkInterfaces.hasMoreElements()) {
        NetworkInterface subNetworkInterface = subNetworkInterfaces.nextElement();
        byte[] hardwareAddress = subNetworkInterface.getHardwareAddress();
        if (hardwareAddress != null) {
          System.out.println(hardwareAddress.length);
        }
      }
    }
  }

  @Test
  public void tes() {
    System.out.println(String.format("%016X", 100L));
  }
}
