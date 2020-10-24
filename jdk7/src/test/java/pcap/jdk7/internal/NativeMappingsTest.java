package pcap.jdk7.internal;

import com.sun.jna.Platform;
import java.util.Arrays;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.runner.RunWith;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

@RunWith(JUnitPlatform.class)
public class NativeMappingsTest {

  @BeforeEach
  void setUp() {
    System.setProperty("pcap.af.inet6", "default");
  }

  @Test
  void libName() {
    Assertions.assertEquals("wpcap", NativeMappings.libName(true));
    Assertions.assertEquals("pcap", NativeMappings.libName(false));
  }

  @Test
  void inetAddress() {
    Assertions.assertNull(NativeMappings.inetAddress(null));

    DefaultAddress.sockaddr sockaddr_in = new DefaultAddress.sockaddr();
    sockaddr_in.sa_family = NativeMappings.AF_INET;
    sockaddr_in.sa_data = new byte[] {0, 0, 127, 0, 0, 1};
    try {
      byte[] address_in = NativeMappings.inetAddress(sockaddr_in).getAddress();
      Assertions.assertArrayEquals(new byte[] {127, 0, 0, 1}, address_in);
    } catch (NullPointerException e) {
      System.out.println("AF_INET6: " + NativeMappings.AF_INET6);
    }

    DefaultAddress.sockaddr sockaddr_in6 = new DefaultAddress.sockaddr();
    sockaddr_in6.sa_family = NativeMappings.AF_INET6;
    sockaddr_in6.sa_data = new byte[] {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    try {
      byte[] address_in6 = NativeMappings.inetAddress(sockaddr_in6).getAddress();
      Assertions.assertArrayEquals(
          new byte[] {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, address_in6);
    } catch (NullPointerException e) {
      System.out.println("AF_INET6: " + NativeMappings.AF_INET6);
    }

    DefaultAddress.sockaddr sockaddr_err = new DefaultAddress.sockaddr();
    sockaddr_err.sa_family = NativeMappings.AF_INET;
    sockaddr_err.sa_data = new byte[] {0};
    Assertions.assertNull(NativeMappings.inetAddress(sockaddr_err));
    sockaddr_err.sa_family = 0;
    Assertions.assertNull(NativeMappings.inetAddress(sockaddr_err));
  }

  @Test
  void errorBuffer() {
    NativeMappings.ErrorBuffer errbuf = new NativeMappings.ErrorBuffer();
    Assertions.assertEquals(Arrays.asList("buf"), errbuf.getFieldOrder());
    Assertions.assertNotNull(errbuf.toString());
  }

  @Test
  void bpfProgram() {
    NativeMappings.bpf_program fp = new NativeMappings.bpf_program();
    Assertions.assertEquals(Arrays.asList("bf_len", "bf_insns"), fp.getFieldOrder());
  }

  @Test
  void bpfInsn() {
    NativeMappings.bpf_insn insn = new NativeMappings.bpf_insn();
    Assertions.assertEquals(Arrays.asList("code", "jt", "jf", "k"), insn.getFieldOrder());
    NativeMappings.bpf_insn.ByReference reference = new NativeMappings.bpf_insn.ByReference();
    Assertions.assertNotNull(reference);
  }

  @Test
  void afInet6() {
    try (MockedStatic<Platform> theMock = Mockito.mockStatic(Platform.class)) {
      theMock
          .when(
              new MockedStatic.Verification() {
                @Override
                public void apply() throws Throwable {
                  Platform.getOSType();
                }
              })
          .thenReturn(Platform.MAC);
      Assertions.assertEquals(30, NativeMappings.defaultAfInet6());
      theMock
          .when(
              new MockedStatic.Verification() {
                @Override
                public void apply() throws Throwable {
                  Platform.getOSType();
                }
              })
          .thenReturn(Platform.KFREEBSD);
      Assertions.assertEquals(28, NativeMappings.defaultAfInet6());
      theMock
          .when(
              new MockedStatic.Verification() {
                @Override
                public void apply() throws Throwable {
                  Platform.getOSType();
                }
              })
          .thenReturn(Platform.LINUX);
      Assertions.assertEquals(10, NativeMappings.defaultAfInet6());
      theMock
          .when(
              new MockedStatic.Verification() {
                @Override
                public void apply() throws Throwable {
                  Platform.getOSType();
                }
              })
          .thenReturn(Platform.WINDOWS);
      Assertions.assertEquals(23, NativeMappings.defaultAfInet6());

      System.setProperty("pcap.af.inet6", "1");
      Assertions.assertEquals(1, NativeMappings.defaultAfInet6());
      System.setProperty("pcap.af.inet6", "0");
      Assertions.assertEquals(0, NativeMappings.defaultAfInet6());
    }
  }
}
