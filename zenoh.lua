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

---------- Helpers ----------
function protect(tbl)
  return setmetatable({}, {
    __index = tbl,
    __newindex = function(t, key, value)
      error("attempting to change constant " ..
      tostring(key) .. " to " .. tostring(value), 2)
    end
  })
end


---------- CONSTANTS ----------
-- whatami --> Zenoh Message Types
ZENOH_WHATAMI = {
  DECLARE         = 0x0b,
  DATA            = 0x0c,
  QUERY           = 0x0d,
  PULL            = 0x0e,
  UNIT            = 0x0f,
  LINK_STATE_LIST = 0x10
}
ZENOH_WHATAMI = protect(ZENOH_WHATAMI)

-- whatami --> Session Message Types
SESSION_WHATAMI = {
  SCOUT      = 0x01,
  HELLO      = 0x02,
  INIT       = 0x03,
  OPEN       = 0x04,
  CLOSE      = 0x05,
  SYNC       = 0x06,
  ACK_NACK   = 0x07,
  KEEP_ALIVE = 0x08,
  PING_PONG  = 0x09,
  FRAME      = 0x0a
}
SESSION_WHATAMI = protect(SESSION_WHATAMI)

-- whatami --> Decorators Message Types
DECORATORS_WHATAMI = {
  ROUTING_CONTEXT = 0x1d,
  REPLY_CONTEXT   = 0x1e,
  ATTACHMENT      = 0x1f
}
DECORATORS_WHATAMI = protect(DECORATORS_WHATAMI)


--- DISSECTOR INFO & FIELDS ---
local proto_zenoh_udp = Proto("zenoh-tcp", "Zenoh Protocol over TCP")
local proto_zenoh_tcp = Proto("zenoh-udp", "Zenoh Protocol over UDP")
local proto_zenoh = Proto("zenoh", "Zenoh Protocol")

-- Zenoh Header
proto_zenoh.fields.header_whatami = ProtoField.uint8("zenoh.whatami", "WhatAmI (Type)", base.HEX)


------ DISSECTOR HELPERS ------

function parse_whatami(tree, whatami)
  if whatami == ZENOH_WHATAMI.DECLARE then
    tree:add(proto_zenoh.fields.header_whatami, whatami, base.u8, "(Declare)")
    return ZENOH_WHATAMI.DECLARE
  elseif whatami == ZENOH_WHATAMI.DATA then
    tree:add(proto_zenoh.fields.header_whatami, whatami, base.u8, "(Data)")
    return ZENOH_WHATAMI.DATA
  elseif whatami == ZENOH_WHATAMI.QUERY then
    tree:add(proto_zenoh.fields.header_whatami, whatami, base.u8, "(Query)")
    return ZENOH_WHATAMI.QUERY
  elseif whatami == ZENOH_WHATAMI.PULL then
    tree:add(proto_zenoh.fields.header_whatami, whatami, base.u8, "(Pull)")
    return ZENOH_WHATAMI.PULL
  elseif whatami == ZENOH_WHATAMI.UNIT then
    tree:add(proto_zenoh.fields.header_whatami, whatami, base.u8, "(Unit)")
    return ZENOH_WHATAMI.UNIT
  elseif bit.band(whatami, 0x1F) == SESSION_WHATAMI.SCOUT then
    tree:add(proto_zenoh.fields.header_whatami, bit.band(whatami, 0x1F), base.u8, "(Scout)")
    return SESSION_WHATAMI.SCOUT
  elseif bit.band(whatami, 0x1F) == SESSION_WHATAMI.HELLO then
    tree:add(proto_zenoh.fields.header_whatami, bit.band(whatami, 0x1F), base.u8, "(Hello)")
    return SESSION_WHATAMI.HELLO
  elseif bit.band(whatami, 0x1F) == SESSION_WHATAMI.INIT then
    tree:add(proto_zenoh.fields.header_whatami, bit.band(whatami, 0x1F), base.u8, "(Init)")
    return SESSION_WHATAMI.INIT
  elseif bit.band(whatami, 0x1F) == SESSION_WHATAMI.OPEN then
    tree:add(proto_zenoh.fields.header_whatami, bit.band(whatami, 0x1F), base.u8, "(Open)")
    return SESSION_WHATAMI.OPEN
  elseif bit.band(whatami, 0x1F) == SESSION_WHATAMI.CLOSE then
    tree:add(proto_zenoh.fields.header_whatami, bit.band(whatami, 0x1F), base.u8, "(Close)")
    return SESSION_WHATAMI.CLOSE
  elseif bit.band(whatami, 0x1F) == SESSION_WHATAMI.SYNC then
    tree:add(proto_zenoh.fields.header_whatami, bit.band(whatami, 0x1F), base.u8, "(Sync)")
    return SESSION_WHATAMI.SYNC
  elseif bit.band(whatami, 0x1F) == SESSION_WHATAMI.ACK_NACK then
    tree:add(proto_zenoh.fields.header_whatami, bit.band(whatami, 0x1F), base.u8, "(ACK-NACK)")
    return SESSION_WHATAMI.ACK_NACK
  elseif bit.band(whatami, 0x1F) == SESSION_WHATAMI.KEEP_ALIVE then
    tree:add(proto_zenoh.fields.header_whatami, bit.band(whatami, 0x1F), base.u8, "(Keep Alive)")
    return SESSION_WHATAMI.KEEP_ALIVE
  elseif bit.band(whatami, 0x1F) == SESSION_WHATAMI.PING_PONG then
    tree:add(proto_zenoh.fields.header_whatami, bit.band(whatami, 0x1F), base.u8, "(Ping Pong)")
    return SESSION_WHATAMI.PING_PONG
  elseif bit.band(whatami, 0x1F) == SESSION_WHATAMI.FRAME then
    tree:add(proto_zenoh.fields.header_whatami, bit.band(whatami, 0x1F), base.u8, "(Frame)")
    return SESSION_WHATAMI.FRAME
  end

  return NULL
end

function parse_header(tree, buf)
  local h_subtree = tree:add(proto_zenoh, buf(), "Header")

  whatami = parse_whatami(h_subtree, buf(0, 1):uint())
end


---------- DISSECTOR ----------
function dissector(buf, pinfo, root, is_tcp)
  if buf:len() < 2 and is_tcp == true then return
  elseif buf:len() == 0 and is_tcp == false then return end

  local i = 0

  local f_size = buf():len()
  if is_tcp == true then
    f_size = buf(i, i + 1):uint()
    i = i + 2
  end

  pinfo.cols.protocol = proto_zenoh.name
  local tree = root:add(proto_zenoh, buf())

  parse_header(tree, buf(i, i + 1))
  i = i + 1
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

