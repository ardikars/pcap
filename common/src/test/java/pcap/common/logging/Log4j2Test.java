/*
 * Copyright (c) 2020 Pcap <contact@pcap.ardikars.com>
 * SPDX-License-Identifier: MIT
 */
package pcap.common.logging;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.runner.RunWith;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
@RunWith(JUnitPlatform.class)
public class Log4j2Test extends AbstractLoggerTest {

  @BeforeEach
  @Override
  public void initLogger() {
    doInitLogger(Log4j2LoggerFactory.getInstance());
  }

  @Test
  @Override
  public void nameTest() {
    doNameTest();
  }

  @Test
  @Override
  public void isEnabledTest() {
    doIsEnabledTest();
  }

  @Test
  @Override
  public void isDebugEnabledTest() {
    doIsDebugEnabledTest();
  }

  @Test
  @Override
  public void isInfoEnabledTest() {
    doIsInfoEnabledTest();
  }

  @Test
  @Override
  public void isWarnEnabledTest() {
    doIsWarnEnabledTest();
  }

  @Test
  @Override
  public void isErrorEnabledTest() {
    doIsErrorEnabledTest();
  }

  @Test
  @Override
  public void logLavelAndMessageTest() {
    doLogLavelAndMessageTest();
  }

  @Test
  @Override
  public void logLevelAndMessageFormatOneTest() {
    doLogLevelAndMessageFormatOneTest();
  }

  @Test
  @Override
  public void logLevelAndMessageFormatTwoTest() {
    doLogLevelAndMessageFormatTwoTest();
  }

  @Test
  @Override
  public void logLevelAndMessageFormatThreeTest() {
    doLogLevelAndMessageFormatThreeTest();
  }

  @Test
  @Override
  public void logLevelAndThrowableTest() {
    doLogLevelAndThrowableTest();
  }

  @Test
  @Override
  public void logLevelAndMessageThrowableTest() {
    doLogLevelAndMessageThrowableTest();
  }

  @Test
  @Override
  public void debugMessageOneTest() {
    doDebugMessageOneTest();
  }

  @Test
  @Override
  public void debugThrowableTest() {
    doDebugThrowableTest();
  }

  @Test
  @Override
  public void debugMessageFormatOneTest() {
    doDebugMessageFormatOneTest();
  }

  @Test
  @Override
  public void debugMessageFormatTwoTest() {
    doDebugMessageFormatTwoTest();
  }

  @Test
  @Override
  public void debugMessageFormatThreeTest() {
    doDebugMessageFormatThreeTest();
  }

  @Test
  @Override
  public void debugMessageThrowableTest() {
    doDebugMessageThrowableTest();
  }

  @Test
  @Override
  public void errorMessageOneTest() {
    doErrorMessageOneTest();
  }

  @Test
  @Override
  public void errorThrowableTest() {
    doErrorThrowableTest();
  }

  @Test
  @Override
  public void errorMessageFormatOneTest() {
    doErrorMessageFormatOneTest();
  }

  @Test
  @Override
  public void errorMessageFormatTwoTest() {
    doErrorMessageFormatTwoTest();
  }

  @Test
  @Override
  public void errorMessageFormatThreeTest() {
    doErrorMessageFormatThreeTest();
  }

  @Test
  @Override
  public void errorMessageThrowableTest() {
    doErrorMessageThrowableTest();
  }

  @Test
  @Override
  public void warnMessageOneTest() {
    doWarnMessageOneTest();
  }

  @Test
  @Override
  public void warnThrowableTest() {
    doWarnThrowableTest();
  }

  @Test
  @Override
  public void warnMessageFormatOneTest() {
    doWarnMessageFormatOneTest();
  }

  @Test
  @Override
  public void warnMessageFormatTwoTest() {
    doWarnMessageFormatTwoTest();
  }

  @Test
  @Override
  public void warnMessageFormatThreeTest() {
    doWarnMessageFormatThreeTest();
  }

  @Test
  @Override
  public void warnMessageThrowableTest() {
    doWarnMessageThrowableTest();
  }

  @Test
  @Override
  public void infoMessageOneTest() {
    doInfoMessageOneTest();
  }

  @Test
  @Override
  public void infoThrowableTest() {
    doInfoThrowableTest();
  }

  @Test
  @Override
  public void infoMessageFormatOneTest() {
    doInfoMessageFormatOneTest();
  }

  @Test
  @Override
  public void infoMessageFormatTwoTest() {
    doInfoMessageFormatTwoTest();
  }

  @Test
  @Override
  public void infoMessageFormatThreeTest() {
    doInfoMessageFormatThreeTest();
  }

  @Test
  @Override
  public void infoMessageThrowableTest() {
    doInfoMessageThrowableTest();
  }
}
