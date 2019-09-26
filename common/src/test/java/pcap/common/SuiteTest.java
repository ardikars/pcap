package pcap.common;

import org.junit.platform.runner.JUnitPlatform;
import org.junit.platform.suite.api.SelectPackages;
import org.junit.runner.RunWith;

@RunWith(JUnitPlatform.class)
@SelectPackages({"pcap.common.logging", "pcap.common.net", "pcap.common.tuple", "pcap.common.util"})
public class SuiteTest {}
