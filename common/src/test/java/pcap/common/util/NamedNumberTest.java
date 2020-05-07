/** This code is licenced under the GPL version 2. */
package pcap.common.util;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.runner.RunWith;
import pcap.common.util.model.HttpStatusCode;

/**
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 * @since 1.0.0
 */
@RunWith(JUnitPlatform.class)
public class NamedNumberTest extends BaseTest {

  public static final int NOT_FOUND_CODE = 404;
  public static final int UNKNOWN_CODE = 10000;
  public static final int INTERNAL_SERVER_ERROR_CODE = 500;

  @Test
  public void found() {
    HttpStatusCode httpStatusCode = HttpStatusCode.valueOf(NOT_FOUND_CODE);
    Assertions.assertTrue(httpStatusCode.equals(HttpStatusCode.NOT_FOUND));
    Assertions.assertEquals(httpStatusCode.hashCode(), HttpStatusCode.NOT_FOUND.hashCode());
    Assertions.assertEquals(httpStatusCode.name(), HttpStatusCode.NOT_FOUND.name());
    Assertions.assertEquals(HttpStatusCode.NOT_FOUND.value(), httpStatusCode.value());
  }

  @Test
  public void notFound() {
    HttpStatusCode httpStatusCode = HttpStatusCode.valueOf(UNKNOWN_CODE);
    Assertions.assertTrue(httpStatusCode.equals(HttpStatusCode.UNKNOWN));
    Assertions.assertEquals(httpStatusCode.hashCode(), HttpStatusCode.UNKNOWN.hashCode());
    Assertions.assertEquals(httpStatusCode.name(), HttpStatusCode.UNKNOWN.name());
    Assertions.assertEquals(HttpStatusCode.UNKNOWN.value(), httpStatusCode.value());
  }

  @Test
  public void notEqualTest() {
    Assertions.assertFalse(HttpStatusCode.UNKNOWN.equals(HttpStatusCode.OK));
    Assertions.assertFalse(HttpStatusCode.UNKNOWN.equals(null));
    Assertions.assertFalse(HttpStatusCode.UNKNOWN.equals(""));
  }

  @Test
  public void toStringTest() {
    Assertions.assertNotNull(HttpStatusCode.OK.toString());
  }

  @Test
  public void registerNewCode() {
    /** Register http status code. */
    HttpStatusCode httpStatusCode =
        new HttpStatusCode(INTERNAL_SERVER_ERROR_CODE, "Internal Server Error.r");
    HttpStatusCode.register(httpStatusCode);

    /** Test */
    HttpStatusCode internalServerError = HttpStatusCode.valueOf(INTERNAL_SERVER_ERROR_CODE);
    Assertions.assertEquals(httpStatusCode.value(), internalServerError.value());
  }
}
