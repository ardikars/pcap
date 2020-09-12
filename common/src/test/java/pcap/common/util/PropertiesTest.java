/** This code is licenced under the GPL version 2. */
package pcap.common.util;

import java.util.UUID;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.runner.RunWith;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
@RunWith(JUnitPlatform.class)
public class PropertiesTest {

  @BeforeEach
  public void before() {
    System.setProperty("jxnet", "jmalloc");
    System.setProperty("jxnet_bool_yes", "yEs");
    System.setProperty("jxnet_bool_1", "1");
    System.setProperty("jxnet_bool_true", "tRuE");
    System.setProperty("jxnet_bool_no", "NO");
    System.setProperty("jxnet_bool_0", "0");
    System.setProperty("jxnet_bool_false", "FALse");
    System.setProperty("jxnet_int_1", "1");
    System.setProperty("jxnet_long_1", "1");
  }

  @Test
  public void getPropertyTest() {
    Assertions.assertTrue(Properties.getProperty("jxnet").equals("jmalloc"));
    Assertions.assertThrows(
        IllegalArgumentException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            Properties.getProperty(null, "");
          }
        });
    Assertions.assertThrows(
        IllegalArgumentException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            Properties.getProperty("", "");
          }
        });
  }

  @Test
  public void getPropertyWithDefaultValueTest() {
    assert Properties.getProperty("jmalloc", "jxnet").equals("jxnet");
  }

  @Test
  public void getBooleanTest() {
    Assertions.assertEquals(Properties.getBoolean("jxnet_bool_yes", false), true);
    Assertions.assertEquals(Properties.getBoolean("jxnet_bool_1", false), true);
    Assertions.assertEquals(Properties.getBoolean("jxnet_bool_true", false), true);
    Assertions.assertEquals(Properties.getBoolean("jxnet_bool_no", true), false);
    Assertions.assertEquals(Properties.getBoolean("jxnet_bool_0", true), false);
    Assertions.assertEquals(Properties.getBoolean("jxnet_bool_false", true), false);
    Assertions.assertEquals(Properties.getBoolean("jxnet_bool_", false), false);
    String idEmpty = UUID.randomUUID().toString();
    System.setProperty(idEmpty, "");
    String idDefault = UUID.randomUUID().toString();
    System.setProperty(idDefault, UUID.randomUUID().toString());
    Assertions.assertEquals(Properties.getBoolean(idEmpty, true), true);
    Assertions.assertEquals(Properties.getBoolean(idDefault, true), true);
  }

  @Test
  public void getIntTest() {
    Assertions.assertEquals(Properties.getInt("jxnet_int_1", 0), 1);
    Assertions.assertEquals(Properties.getInt("jxnet_int", 0), 0);
    Assertions.assertEquals(Properties.getInt("jxnet_int", 0), 0);
    String id = UUID.randomUUID().toString();
    System.setProperty(id, "a");
    Assertions.assertEquals(Properties.getInt(id, 0), 0);
  }

  @Test
  public void getLongTest() {
    Assertions.assertEquals(Properties.getLong("jxnet_long_1", 0), 1);
    Assertions.assertEquals(Properties.getLong("jxnet_long", 0), 0);
    String id = UUID.randomUUID().toString();
    System.setProperty(id, "a");
    Assertions.assertEquals(Properties.getLong(id, 0), 0);
  }
}
