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
local proto_zenoh_udp = Proto("zenoh-tcp", "Zenoh Protocol over TCP")
local proto_zenoh_tcp = Proto("zenoh-udp", "Zenoh Protocol over UDP")
local proto_zenoh = Proto("zenoh", "Zenoh Protocol")


---------- DISSECTOR ----------
function dissector(buf, pinfo, root, is_tcp)
  if buf:len() < 2 and is_tcp == true then return
  elseif buf:len() == 0 and is_tcp == false then return end

  i = 0
  if is_tcp == true then
    f_size = buf(i, i + 1)
    i = i + 2
  else
    f_size = buf():len()
  end

  pinfo.cols.protocol = proto_zenoh.name
  local tree = root:add(proto_zenoh, buf())
end

function proto_zenoh_udp.dissector(buf, pinfo, root)
    dissector(buf, pinfo, root, false)
end

function proto_zenoh_tcp.dissector(buf, pinfo, root)
    dissector(buf, pinfo, root, true)
end

-- register zenoh to handle ports
--  * 7447/tcp : the zenoh protocol via TCP
--  * 7447/udp : the zenoh scouting protocol using UDP multicast
do
    local tcp_port_table = DissectorTable.get("tcp.port")
    tcp_port_table:add(7447, proto_zenoh_tcp)

    local udp_port_table = DissectorTable.get("udp.port")
    udp_port_table:add(7447, proto_zenoh_udp)
end

