/*
 * Copyright (c) 2020 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.jdk7.internal;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.runner.RunWith;
import pcap.spi.annotation.Version;
import pcap.spi.exception.ErrorException;

@RunWith(JUnitPlatform.class)
public class UtilsTest {

  @Test
  public void emptyTest() {
    Assertions.assertTrue(Utils.empty(null));
    Assertions.assertTrue(Utils.empty(""));
  }

  @Test
  public void blankTest() {
    Assertions.assertTrue(Utils.blank(" "));
    Assertions.assertTrue(Utils.blank(""));
    Assertions.assertTrue(Utils.blank(null));
    Assertions.assertTrue(Utils.blank("\t "));
    Assertions.assertTrue(Utils.blank("\r "));
    Assertions.assertTrue(Utils.blank("\n "));
    Assertions.assertFalse(Utils.blank("\0 "));
    Assertions.assertFalse(Utils.blank("abc"));
  }

  @Test
  public void getVersion() {
    Assertions.assertNotNull(Utils.getVersion(UtilsTest.class, "testAnnotation"));
    Assertions.assertNull(Utils.getVersion(UtilsTest.class, "testAnnotations"));
  }

  @Test
  public void validateVersion() throws ErrorException {
    Utils.validateVersion(null);
    final Version version = Utils.getVersion(UtilsTest.class, "testAnnotation");
    Assertions.assertThrows(
        ErrorException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            Utils.validateVersion(version);
          }
        });
  }

  @Test
  public void isValidVersion() {
    Assertions.assertTrue(true);
  }

  @Version(major = Integer.MAX_VALUE, minor = 0, patch = 0)
  public void testAnnotation() {}
}
