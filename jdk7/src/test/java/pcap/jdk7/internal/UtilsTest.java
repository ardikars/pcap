/*
 * Copyright (c) 2020-2021 Pcap Project
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
    Assertions.assertTrue(Utils.blank("\0 "));
    Assertions.assertFalse(Utils.blank("abc"));
  }

  @Test
  public void isValidVersion() throws ErrorException {
    Assertions.assertThrows(
        ErrorException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            Utils.validateVersion(Integer.MAX_VALUE, Integer.MAX_VALUE, Integer.MAX_VALUE);
          }
        });
    Utils.validateVersion(0, 0, 0);
  }

  @Test
  public void isSupported() {
    Assertions.assertTrue(Utils.isSupported(Utils.MAJOR, Utils.MINOR, Utils.PATCH));

    Assertions.assertTrue(Utils.isSupported(Utils.MAJOR - 1, 0, 0));
    Assertions.assertTrue(Utils.isSupported(Utils.MAJOR, Utils.MINOR - 1, 0));
    Assertions.assertTrue(Utils.isSupported(Utils.MAJOR, Utils.MINOR, Utils.PATCH - 1));

    Assertions.assertFalse(Utils.isSupported(Utils.MAJOR + 1, 0, 0));
    Assertions.assertFalse(Utils.isSupported(Utils.MAJOR, Utils.MINOR + 1, 0));
    Assertions.assertFalse(Utils.isSupported(Utils.MAJOR, Utils.MINOR, Utils.PATCH + 1));
  }

  @Test
  public void warn() {
    Utils.warn("");
  }

  @Test
  public void doLog() {
    Utils.doLog(false, "");
    Utils.doLog(true, "");
  }

  @Version(major = Integer.MAX_VALUE, minor = 0, patch = 0)
  public void testAnnotation() {}
}
