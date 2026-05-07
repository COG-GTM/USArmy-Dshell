import unittest
from unittest.mock import patch

import pcapy

from dshell.util import count_live_interfaces


class TestCountLiveInterfaces(unittest.TestCase):
    @patch("dshell.util.pcapy")
    def test_count_returns_length(self, mock_pcapy):
        mock_pcapy.findalldevs.return_value = ["eth0", "lo", "wlan0"]
        self.assertEqual(count_live_interfaces(), 3)

    @patch("dshell.util.pcapy")
    def test_count_returns_zero_on_no_interfaces(self, mock_pcapy):
        mock_pcapy.findalldevs.return_value = []
        self.assertEqual(count_live_interfaces(), 0)

    @patch("dshell.util.pcapy")
    def test_count_returns_zero_on_error(self, mock_pcapy):
        mock_pcapy.PcapError = pcapy.PcapError
        mock_pcapy.findalldevs.side_effect = pcapy.PcapError("permission denied")
        self.assertEqual(count_live_interfaces(), 0)


if __name__ == "__main__":
    unittest.main()
