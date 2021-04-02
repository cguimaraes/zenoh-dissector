## Zenoh Protocol Dissector For Wireshark
## Copyright (C) 2021  Carlos Guimarães
##
## This program is free software: you can redistribute it and/or modify
## it under the terms of the GNU General Public License as published by
## the Free Software Foundation, either version 3 of the License, or
## (at your option) any later version.
##
## This program is distributed in the hope that it will be useful,
## but WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
## GNU General Public License for more details.
##
## You should have received a copy of the GNU General Public License
## along with this program.  If not, see <https://www.gnu.org/licenses/>.

import unittest
import pyshark

class TestInit(unittest.TestCase):
  def test_all_fields(self):
    pass

  def test_only_mandatory(self):
    trace = pyshark.FileCapture('./traces/zenoh-init.pcap')
    for field in trace[0].get_multiple_layers('ZENOH')[0].field_names:
      val = trace[0].get_multiple_layers('ZENOH')[0].get_field(field)
      if field == "len":
        self.assertEqual(val, '12')
      elif field == "msgid":
        self.assertEqual(val, '0x00000003')
      elif field == "init_flags":
        self.assertEqual(val, '0x00000000')
      elif field == "init_v_maj":
        self.assertEqual(val, '0')
      elif field == "init_v_min":
        self.assertEqual(val, '0')
      elif field == "init_whatami":
        self.assertEqual(val, '4')
      elif field == "init_peerid":
        self.assertEqual(val, '342c572ef3c884ea')

if __name__ == '__main__':
    unittest.main()

