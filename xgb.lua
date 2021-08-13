local lsis_xgt_protocol = Proto("LSIS_XGT",  "XGT dedicated protocol")

local lsis_id = ProtoField.string("lsis_xgt.lsis_id", "lsis id", base.ASCII)
local plc_info = ProtoField.uint16("lsis_xgt.plc_info", "plc info", base.HEX)
local cpu_info = ProtoField.uint8("lsis_xgt.cpu_info", "cpu info", base.HEX)
local frame_direction_names = {
	[0x33] = "Request frame",
	[0x11] = "Response frame"
}
local frame_direction = ProtoField.uint8("lsis_xgt.frame_direction", "frame direction", base.HEX, frame_direction_names)
local frame_order_no = ProtoField.uint16("lsis_xgt.frame_order_no", "frame order no", base.HEX)
local lsis_length = ProtoField.uint16("lsis_xgt.length", "length", base.HEX)
local position_info = ProtoField.uint8("lsis_xgt.position_info", "position info", base.HEX)
local check_sum = ProtoField.uint8("lsis_xgt.check_sum", "check sum", base.HEX)
local command_instruction_names = {
	[0x54] = "Read",
	[0x55] = "Response for reading",
	[0x58] = "Write",
	[0x59] = "Response for writing"
}
local command = ProtoField.uint16("lsis_xgt.command", "command instruction", base.HEX, command_instruction_names)
local data_type_names = {
	[0x0] = "Bit",
	[0x1] = "Byte",
	[0x2] = "Word",
	[0x3] = "DWord",
	[0x4] = "LWord",
	[0x14] = "Continuous"
}
local data_type = ProtoField.uint16("lsis_xgt.data_type", "data type", base.HEX, data_type_names)
local reserved_area = ProtoField.uint16("lsis_xgt.reserved_area", "reserved area", base.HEX)
local number_of_blocks = ProtoField.uint16("lsis_xgt.number_of_blocks", "number of blocks", base.HEX)
local length_of_variables = ProtoField.uint8("lsis_xgt.length_of_variables", "length of variables", base.HEX)
local data_address = ProtoField.bytes("lsis_xgt.data_address", "data address")
local data_count = ProtoField.uint16("lsis_xgt.data_count", "number of data", base.DEC)
local error_status = ProtoField.uint16("lsis_xgt.error_status", "error status", base.HEX)
local block_num = ProtoField.uint16("lsis_xgt.block_num", "block number", base.HEX)
local data = ProtoField.bytes("lsis_xgt.data", "data")

lsis_xgt_protocol.fields = {
	lsis_id,
	plc_info,
	cpu_info,
	frame_direction,
	frame_order_no,
	lsis_length,
	position_info,
	check_sum,
	command,
	data_type,
	reserved_area,
	number_of_blocks,
	length_of_variables,
	data_address,
	data_count,
	error_status,
	block_num,
	data
}

function lsis_xgt_protocol.dissector(buffer, pinfo, tree)
	length = buffer:len()
	if length == 0 then return end

	pinfo.cols.protocol = lsis_xgt_protocol.name

	local subtree = tree:add(lsis_xgt_protocol, buffer(), "XGT dedicated protocol")

	subtree:add(lsis_id, buffer(0, 10))
	subtree:add_le(plc_info, buffer(10, 2))
	subtree:add_le(cpu_info, buffer(12, 1))
	subtree:add_le(frame_direction, buffer(13, 1))
	subtree:add_le(frame_order_no, buffer(14, 2))
	subtree:add_le(lsis_length, buffer(16, 2))
	subtree:add_le(position_info, buffer(18, 1))
	subtree:add_le(check_sum, buffer(19, 1))
	subtree:add_le(command, buffer(20, 2))
	subtree:add_le(data_type, buffer(22, 2))
	subtree:add_le(reserved_area, buffer(24, 2))
	local cmd = buffer(20, 2):le_int()
	if cmd == 0x55 or cmd == 0x59 then
		subtree:add_le(error_status, buffer(26, 2))
		local cmd = buffer(20, 2):le_int()
		if cmd == 0x55 then
			subtree:add_le(block_num, buffer(28, 2))
			subtree:add_le(data_count, buffer(30, 2))
			local len = buffer(30, 2):le_int()
			if 32 + len <= length then
				subtree:add_le(data, buffer(32, len))
			end
		end
	elseif cmd == 0x54 or cmd == 0x58 then
		subtree:add_le(number_of_blocks, buffer(26, 2))
		subtree:add_le(length_of_variables, buffer(28, 2))
		local len = buffer(28, 2):le_int()
		if len + 30 + 2 <= length then
			subtree:add_le(data_address, buffer(30, len)):append_text(" (" .. buffer(30, len):string() ..")")
			subtree:add_le(data_count, buffer(30 + len, 2))
		else
			print("The length of the data address is out of the packet. len is:" .. len)
		end
	end

end

local tcp_port = DissectorTable.get("tcp.port")
tcp_port:add(2004, lsis_xgt_protocol)
