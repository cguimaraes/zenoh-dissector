-- Zenoh Protocol Dissector For Wireshark
-- Copyright (C) 2021  Carlos Guimarães
--
-- This program is free software: you can redistribute it and/or modify
-- it under the terms of the GNU General Public License as published by
-- the Free Software Foundation, either version 3 of the License, or
-- (at your option) any later version.

-- This program is distributed in the hope that it will be useful,
-- but WITHOUT ANY WARRANTY; without even the implied warranty of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
-- GNU General Public License for more details.
--
-- You should have received a copy of the GNU General Public License
-- along with this program.  If not, see <https://www.gnu.org/licenses/>.
--

------- DISSECTOR INFO --------
local proto_zenoh = Proto("zenoh", "Zenoh Protocol")


---------- DISSECTOR ----------
function proto_zenoh.dissector(buf, pinfo, root)
  if buf:len() == 0 then return end

  pinfo.cols.protocol = proto_zenoh.name
  local tree = root:add(proto_zenoh, buf())
  i = 0
end

-- register zenoh to handle ports
--  * 7447/tcp : the zenoh protocol via TCP
--  * 7447/udp : the zenoh scouting protocol using UDP multicast
do
    local tcp_port_table = DissectorTable.get("tcp.port")
    tcp_port_table:add(7447, proto_zenoh)

    local udp_port_table = DissectorTable.get("udp.port")
    udp_port_table:add(7447, proto_zenoh)
end

