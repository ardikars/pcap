package pcap.codec.tcp;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.runner.RunWith;

@RunWith(JUnitPlatform.class)
public class TcpFlagsTest {

  private TcpFlags.Builder builder() {
    return new TcpFlags.Builder()
        .ack(true)
        .cwr(true)
        .ece(true)
        .fin(true)
        .ns(true)
        .psh(true)
        .rst(true)
        .syn(true)
        .urg(true);
  }

  @Test
  public void buildTest() {
    final TcpFlags.Builder builder = builder();
    Assertions.assertNotNull(builder);
    Assertions.assertNotNull(builder.build());
  }

  @Test
  public void compareTest() {
    final TcpFlags.Builder builder = builder();
    final TcpFlags flags = builder.build();
    final TcpFlags fromValue = new TcpFlags.Builder().build(flags.value());
    Assertions.assertEquals(flags, fromValue);
    Assertions.assertEquals(flags.hashCode(), fromValue.hashCode());
    Assertions.assertEquals(flags.value(), fromValue.value());
    Assertions.assertEquals(flags.isAck(), fromValue.isAck());
    Assertions.assertEquals(flags.isCwr(), fromValue.isCwr());
    Assertions.assertEquals(flags.isEce(), fromValue.isEce());
    Assertions.assertEquals(flags.isFin(), fromValue.isFin());
    Assertions.assertEquals(flags.isNs(), fromValue.isNs());
    Assertions.assertEquals(flags.isPsh(), fromValue.isPsh());
    Assertions.assertEquals(flags.isRst(), fromValue.isRst());
    Assertions.assertEquals(flags.isSyn(), fromValue.isSyn());
    Assertions.assertEquals(flags.isUrg(), fromValue.isUrg());
    Assertions.assertEquals(flags, fromValue);
  }

  @Test
  public void toStringTest() {
    Assertions.assertNotNull(builder().build().toString());
  }
}
