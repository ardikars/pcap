/*
 * Copyright (c) 2020-2023 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.spi.exception;

/**
 * Error codes for the pcap API. These will all be negative, so you can check for the success or
 * failure of a call that returns these codes by checking for a negative value.
 *
 * <p>Generic error code ({@code -1}).
 *
 * @since 1.0.0
 */
public class ErrorException extends Exception {

  // #define PCAP_ERROR                          -1  /* generic error code */
  // #define PCAP_ERROR_BREAK                    -2  /* loop terminated by pcap_breakloop */
  // #define PCAP_ERROR_NOT_ACTIVATED            -3  /* the capture needs to be activated */
  // #define PCAP_ERROR_ACTIVATED                -4  /* the operation can't be performed on already
  // activated captures */
  // #define PCAP_ERROR_NO_SUCH_DEVICE           -5  /* no such device exists */
  // #define PCAP_ERROR_RFMON_NOTSUP             -6  /* this device doesn't support rfmon (monitor)
  // mode */
  // #define PCAP_ERROR_NOT_RFMON                -7  /* operation supported only in monitor mode */
  // #define PCAP_ERROR_PERM_DENIED              -8  /* no permission to open the device */
  // #define PCAP_ERROR_IFACE_NOT_UP             -9  /* interface isn't up */
  // #define PCAP_ERROR_CANTSET_TSTAMP_TYPE      -10 /* this device doesn't support setting the
  // time stamp type */
  // #define PCAP_ERROR_PROMISC_PERM_DENIED	     -11 /* you don't have permission to capture in
  // promiscuous mode */
  // #define PCAP_ERROR_TSTAMP_PRECISION_NOTSUP  -12 /* the requested time stamp precision is not
  // supported */

  /**
   * Create new ErrorException instance.
   *
   * @param message message.
   * @since 1.0.0
   */
  public ErrorException(String message) {
    super(message);
  }
}
