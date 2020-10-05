package pcap.spi.option;

import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.runner.RunWith;

@RunWith(JUnitPlatform.class)
public class DefaultEventOptionsTest {

  private DefaultEventOptions options;

  @BeforeEach
  public void setUp() {
    this.options = new DefaultEventOptions();
  }

  @Test
  public void timeout() {
    options.timeout(1, TimeUnit.SECONDS);
    Assertions.assertEquals(1000, options.timeout());
  }
}
