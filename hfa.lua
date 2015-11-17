p_hfa = Proto("hfa", "HFA")

p_hfa.prefs["tcp_port"] = Pref.uint("TCP Port", 4060, "HFA TCP Port")

local f_length = ProtoField.uint16("hfa.length", "Message Length", base.DEC)
local f_msgtype = ProtoField.uint8("hfa.msgtype", "Message Type", base.HEX)

p_hfa.fields = { f_length, f_msgtype }

local msg_types = {
	[0x04] = { "hfa_register", "Register" },
	[0x20] = { "hfa_request", "Stimulus Request" },
	[0x28] = { "hfa_alive_request", "Alive Request" },
	[0x2a] = { 'hfa_alive_response', "Alive Response" },
	[0x31] = { "hfa_set_media", "Set Payload" }
};


function p_hfa.dissector(buf, pinfo, root)
	pinfo.cols.protocol = p_hfa.name
	subtree = root:add(p_hfa, buf(0))

	local len = buf(0, 2):uint()
	subtree:add(f_length, buf(0, 2))



	local msgtype = subtree:add(f_msgtype, buf(10, 1))
	if msg_types[buf(10, 1):uint()] ~= nil then
		msgtype:append_text(" (" .. msg_types[buf(10, 1):uint()][2] .. ")")
	end

	if msg_types[buf(10, 1):uint()] ~= nil then
		if msg_types[buf(10, 1):uint()][1] ~= nil then
			local dissector_name = msg_types[buf(10, 1):uint()][1]
			Dissector.get(dissector_name):call(buf(11):tvb(), pinfo, msgtype)
		end
	end

	return len
end

function p_hfa.init()
	local tcp_port_dissector_table = DissectorTable.get("tcp.port")
	tcp_port_dissector_table:add(p_hfa.prefs["tcp_port"], p_hfa)
end

p_alive_request = Proto("hfa_alive_request", "Alive Request")
p_alive_request.fields.timestamp = ProtoField.absolute_time("hfa.alive_request.timestamp", "Timestamp", FT_ABSOLUTE_TIME)

function p_alive_request.dissector(buf, pinfo, root)
	pinfo.cols['info'] = "Alive Request"
	if buf:len() == 3 then
		pinfo.cols['info'] = "Alive Request (Startup)"
	elseif buf:len() > 0 then
		root:add(p_alive_request.fields.timestamp, buf(6, 4))
	end
end

p_alive_response = Proto("hfa_alive_response", "Alive Response")

function p_alive_response.dissector(buf, pinfo, root)
	pinfo.cols['info'] = "Alive Response"
end

p_request = Proto("hfa_request", "Request")

p_request.fields.request_type = ProtoField.uint8("hfa.request.type", "Request Type", base.HEX)

local request_types = {
	[0x01] = { "Control Key Module", "request_control_keymodule" },
	[0x40] = { "Key Control", "request_key" },
	[0x41] = { "Hookswitch Off-Hook"},
	[0x42] = { "Hookswitch On-Hook"},
	[0x43] = { "Set Display", "request_set_display" },
	[0x45] = { "Ringer", "request_ringer" },
	[0x54] = { "Set Audio", "request_set_audio" },
	[0x5b] = { "Set Ringer Volume", "request_set_ringer_volume" },
	[0x5e] = { "Setup Menu", "request_setup_menu" },
	[0x60] = { "Part Number", "request_part_number" },
	[0x6b] = { "Set FPK Text", "request_set_fpk_text" },
	[0x6e] = { "Set FPK Level", "request_set_fpk_level" },
	[0x72] = { "Set Menu Item", "request_set_menu_item" }
};

function p_request.dissector(buf, pinfo, root)
	local request_type = root:add(p_request.fields.request_type, buf(0, 1), buf(0, 1):uint())
	if request_types[buf(0, 1):uint()] ~= nil then
		request_type:append_text(" (" .. request_types[buf(0, 1):uint()][1] .. ")")
		pinfo.cols['info'] = request_types[buf(0, 1):uint()][1]
		if request_types[buf(0, 1):uint()][2] ~= nil then
			local dissector_name = request_types[buf(0, 1):uint()][2]
			Dissector.get(dissector_name):call(buf(1):tvb(), pinfo, request_type)
		end
	else
		request_type:add_expert_info(PI_UNDECODED, PI_WARN, "Unknown Request Type")
		pinfo.cols['info'] = "Unknown Request Type 0x" .. buf(0, 1)
	end
end

local VALS_DIRECTION = {
	[0x00] = "No Payload",
	[0x01] = "Receive",
	[0x02] = "Send",
	[0x03] = "Send / Receive"	
}

local VALS_UNKNOWN = {
	[0x00] = "Unknown"
}

p_set_media = Proto("hfa_set_media", "Set Payload")
p_set_media.fields.local_port = ProtoField.uint16("hfa.payload.local_port", "Local Port", base.DEC)
p_set_media.fields.local_address = ProtoField.string("hfa.payload.local_address", "Local Address", FT_STRINGZ)
p_set_media.fields.flags = ProtoField.uint8("hfa.payload.flags", "Flags", base.HEX)
p_set_media.fields.flag_unknown_first = ProtoField.uint8("hfa.payload.flags.unknown_first", "Unknown", base.DEC, VALS_UNKNOWN, 0xF0, "Unknown")
p_set_media.fields.flag_direction = ProtoField.uint8("hfa.payload.flags.direction", "Direction", base.DEC, VALS_DIRECTION, 0xC, "Direction")
p_set_media.fields.flag_unknown_last = ProtoField.uint8("hfa.payload.flags.unknown_last", "Unknown", base.DEC, VALS_UNKNOWN, 0x3, "Unknown")

function p_set_media.dissector(buf, pinfo, root)
	root:add(p_set_media.fields.local_port, buf(9, 2), buf(9, 2):uint())
	root:add(p_set_media.fields.local_address, buf(19), buf(19):stringz())
	local flags = root:add(p_set_media.fields.flags, buf(2, 1), buf(2, 1):uint())
	flags:add(p_set_media.fields.flag_unknown_first, buf(2, 1))
	flags:add(p_set_media.fields.flag_direction, buf(2, 1))
	flags:add(p_set_media.fields.flag_unknown_last, buf(2, 1))
	pinfo.cols['info'] = "Set Payload [local_port=" .. buf(9, 2):uint() .. ", local_address=" .. buf(19):stringz() .. "]"
end



p_set_display = Proto("request_set_display", "Set Display")
p_set_display.fields.display_row = ProtoField.uint8("hfa.set_display.row", "Row", base.DEC)
p_set_display.fields.display_col = ProtoField.uint8("hfa.set_display.col", "Column", base.DEC)
p_set_display.fields.display_content = ProtoField.string("hfa.set_display.content", "Content", FT_STRING)

function p_set_display.dissector(buf, pinfo, root)
	root:add(p_set_display.fields.display_row, buf(0, 1))
	root:add(p_set_display.fields.display_col, buf(1, 1))
	root:add(p_set_display.fields.display_content, buf(3), "\"" .. buf(3):string() .. "\"")
	pinfo.cols['info'] = "Set Display [row=" .. buf(0, 1) .. ", col=" .. buf(1, 1) .. "]: " .. buf(3):string()
end

VALS_KEYS = {
	[0x01] = "1",
	[0x02] = "2",
	[0x03] = "3",
	[0x04] = "4",
	[0x05] = "5",
	[0x06] = "6",
	[0x07] = "7",
	[0x08] = "8",
	[0x09] = "9",
	[0x0a] = "0",
	[0x0b] = "*",
	[0x0c] = "#",
	[0x0d] = "VOL+",
	[0x0e] = "VOL-",
	[0x0f] = "<",
	[0x10] = ">",
	[0x11] = "OK",
	[0x12] = "FPK1",
	[0x13] = "FPK2",
	[0x14] = "FPK3",
	[0x15] = "FPK4",
	[0x16] = "FPK5",
	[0x17] = "FPK6",
	[0x18] = "FPK7",
	[0x19] = "FPK8",
	[0x1a] = "FPK9",
	[0x1b] = "FPK10",
	[0x1c] = "FPK11",
	[0x1d] = "FPK12",
	[0x1e] = "FPK13",
	[0x1f] = "FPK14",
	[0x20] = "FPK15",
	[0x21] = "FPK16",
	[0x22] = "FPK17",
	[0x23] = "FPK18",
	[0x24] = "FPK19",
	[0x25] = "FPK20"
}

VALS_LED = {
	[0x00] = "Off",
	[0x01] = "On"
}

p_key = Proto("request_key", "Key")
p_key.fields.key = ProtoField.uint8("hfa.key.key", "Key", base.DEC, VALS_KEYS, 0x3F, "Key")
p_key.fields.led = ProtoField.uint8("hfa.key.led", "LED", base.DEC, VALS_LED, 0xFF, "LED")

function p_key.dissector(buf, pinfo, root)
	if buf:len() == 1 then
		if VALS_KEYS[buf(0, 1):uint() % 0x40] ~= nil then
			pinfo.cols['info'] = "Key Press: " .. VALS_KEYS[buf(0, 1):uint() % 0x40]
		else
			pinfo.cols['info'] = "Key Press: Unknown (0x" .. buf(0, 1) .. ")"
		end
		root:add(p_key.fields.key, buf(0, 1))
	elseif buf:len() == 2 then
		if VALS_KEYS[buf(0, 1):uint() % 0x40] ~= nil then
			pinfo.cols['info'] = "LED " .. VALS_KEYS[buf(0, 1):uint() % 0x40] .. " " .. VALS_LED[buf(1, 1):uint()]
		end
		root:add(p_key.fields.key, buf(0, 1))
		root:add(p_key.fields.led, buf(1, 1))
	end
end

VALS_MIC_MUTE = {
	[0x00] = "Muted",
	[0x01] = "Enabled"
}

p_set_audio = Proto("request_set_audio", "Set Audio")
p_set_audio.fields.flags = ProtoField.uint8("hfa.set_audio.flags", "Flags", base.HEX)
p_set_audio.fields.flag_mic_mute = ProtoField.uint8("hfa.set_audio.flag_mic_mute", "Microphone", base.DEC, VALS_MIC_MUTE, 0x10, "Microphone")
p_set_audio.fields.volume = ProtoField.uint8("hfa.set_audio.volume", "Volume", base.DEC)

function p_set_audio.dissector(buf, pinfo, root)
	local flags = root:add(p_set_audio.fields.flags, buf(0, 1), buf(0, 1):uint())
	flags:add(p_set_audio.fields.flag_mic_mute, buf(0, 1))
	root:add(p_set_audio.fields.volume, buf(1, 1), ((buf(1, 1):uint() % 0x10) + 1))
	pinfo.cols['info'] = "Set Audio [volume=" .. ((buf(1, 1):uint() % 0x10) + 1) .. "]"
end

p_set_ringer_volume = Proto("request_set_ringer_volume", "Set Ringer Volume")
p_set_ringer_volume.fields.volume = ProtoField.uint8("hfa.set_ringer_volume.volume", "Volume", base.DEC)

function p_set_ringer_volume.dissector(buf, pinfo, root)
	root:add(p_set_ringer_volume.fields.volume, buf(0, 1), buf(0, 1):uint() + 1)
	pinfo.cols['info'] = "Set Ringer Volume " .. (buf(0, 1):uint() + 1)
end

VALS_RINGER = {
	[0x00] = "Off",
	[0x01] = "On"
}

p_ringer = Proto("request_ringer", "Ringer")
p_ringer.fields.on = ProtoField.uint8("hfa.ringer.on", "Ringer", base.DEC, VALS_RINGER, 0x01, "Ringer")

function p_ringer.dissector(buf, pinfo, root)
	root:add(p_ringer.fields.on, buf(0, 1))
	local status = ""
	if bit.band(buf(0, 1):uint(), 0x01) == 0x01 then
		status = "On"
	else
		status = "Off"
	end
	pinfo.cols['info'] = "Ringer " .. status
end

p_set_fpk_level = Proto("request_set_fpk_level", "Set FPK Level")
p_set_fpk_level.fields.level = ProtoField.uint8("hfa.fpk_level.level", "Level")

function p_set_fpk_level.dissector(buf, pinfo, root)
	pinfo.cols['info'] = "Set FPK Level " .. buf(0, 1):uint()
	root:add(p_set_fpk_level.fields.level, buf(0, 1))
end

p_set_fpk_text = Proto("request_set_fpk_text", "Set FPK Text")
p_set_fpk_text.fields.level = ProtoField.uint8("hfa.fpk_text.level", "Level")
p_set_fpk_text.fields.key = ProtoField.uint8("hfa.fpk_text.key", "Key")
p_set_fpk_text.fields.key_index = ProtoField.uint8("hfa.fpk_text.index", "Index")
p_set_fpk_text.fields.key_length = ProtoField.uint8("hfa.fpk_text.length", "Length")
p_set_fpk_text.fields.key_text = ProtoField.string("hfa.fpk_text.text", "Text", FT_STRING)

function p_set_fpk_text.dissector(buf, pinfo, root)
	root = root:add(p_set_fpk_text.fields.level, buf(0, 1))
	pinfo.cols['info'] = "Set FPK Text - Level " .. buf(0, 1):uint()
	local i = 1
	while i < buf:len() do
		local index = buf(i, 1):uint() - 0x11
		local length = buf(i + 1, 1):uint()
		local key = root:add(p_set_fpk_text.fields.key, buf(i, length + 2), index)
		key:add(p_set_fpk_text.fields.key_index, buf(i, 1), index)
		key:add(p_set_fpk_text.fields.key_length, buf(i + 1, 1), length)
		if length > 0 then
			key:add(p_set_fpk_text.fields.key_text, buf(i + 2, length))
			key:append_text(" - " .. buf(i + 2, length):string())
		end
		i = i + length + 2
	end
end

p_control_keymodule = Proto("request_control_keymodule", "Set Keymodule Text")
p_control_keymodule.fields.level = ProtoField.uint8("hfa.keymodule_text.level", "Level")
p_control_keymodule.fields.module = ProtoField.uint8("hfa.keymodule_text.module", "Module")
p_control_keymodule.fields.key = ProtoField.uint8("hfa.keymodule_text.key", "Key")
p_control_keymodule.fields.key_index = ProtoField.uint8("hfa.keymodule_text.index", "Index")
p_control_keymodule.fields.key_length = ProtoField.uint8("hfa.keymodule_text.length", "Length")
p_control_keymodule.fields.key_text = ProtoField.string("hfa.keymodule_text.text", "Text", FT_STRING)

function p_control_keymodule.dissector(buf, pinfo, root)
	if buf(0, 1):uint() == 0x11 then -- Keymodule Key Press
		root:add(p_control_keymodule.fields.key, buf(1, 1), buf(1, 1):uint() - 0x40)
		pinfo.cols['info'] = "Keymodule Key Press " .. buf(1, 1):uint() - 0x40
	elseif buf(0, 1):uint() == 0x12 then -- set Keymodule text
		pinfo.cols['info'] = "Set Keymodule Text"
		root:add(p_control_keymodule.fields.module, buf(0, 1), buf(0, 1):uint() - 0x11)
		root = root:add(p_control_keymodule.fields.level, buf(1, 1))
		local i = 2
		while i < buf:len() do
			local index = buf(i, 1):uint()
			local length = buf(i + 1, 1):uint()
			local key = root:add(p_control_keymodule.fields.key, buf(i, length + 2), index)
			key:add(p_control_keymodule.fields.key_index, buf(i, 1), index)
			key:add(p_control_keymodule.fields.key_length, buf(i + 1, 1), length)
			if length > 0 then
				key:add(p_control_keymodule.fields.key_text, buf(i + 2, length))
				key:append_text(" - " .. buf(i + 2, length):string())
			end
			i = i + length + 2
		end
	end
end

p_setup_menu = Proto("request_setup_menu", "Setup Menu")
p_setup_menu.fields.num_items = ProtoField.uint8("hfa.setup_menu.num_items", "Item Count")
p_setup_menu.fields.itemid = ProtoField.uint8("hfa.setup_menu.itemid", "Menu Item ID")

function p_setup_menu.dissector(buf, pinfo, root)
	local numItems = buf(0, 1):uint()
	local menu = root:add(p_setup_menu.fields.num_items, buf(0, 1), numItems)
	local i = 0
	while i < numItems do
		menu:add(p_setup_menu.fields.itemid, buf(i * 2 + 1, 2), buf(i * 2 + 2, 1):uint())
		i = i + 1
	end
end

p_set_menu_item = Proto("request_set_menu_item", "Set Menu Item")
p_set_menu_item.fields.item = ProtoField.uint8("hfa.menu_item", "Menu Item")
p_set_menu_item.fields.length = ProtoField.uint8("hfa.menu_item.length", "Length")
p_set_menu_item.fields.key_text = ProtoField.string("hfa.menu_item.text", "Text", FT_STRING)

function p_set_menu_item.dissector(buf, pinfo, root)
	local infoText = "Set Menu Item"
	local i = 0
	while i < buf:len() do
		local itemid = buf(i + 1, 1):uint()
		local item_length = buf(i + 2, 1):uint()
		local item = root:add(p_set_menu_item.fields.item, buf(i, item_length + 3), buf(i + 1, 1):uint())
		item:add(p_set_menu_item.fields.length, buf(i + 2, 1))
		item:add(p_set_menu_item.fields.key_text, buf(i + 3, item_length))
		infoText = infoText .. " " .. itemid .. ": " .. buf(i + 3, item_length):string()
		i = i + item_length + 3
	end

	pinfo.cols['info'] = infoText
end

p_hfa_register = Proto("hfa_register", "Register")
p_hfa_register.fields.information_element = ProtoField.uint8("hfa.register.information_element", "Information Element", base.HEX)
p_hfa_register.fields.information_element_length = ProtoField.uint16("hfa.register.information_element.length", "Length")
p_hfa_register.fields.mac_address = ProtoField.bytes("hfa.register.mac_address", "MAC-Address")
p_hfa_register.fields.subscriber_number = ProtoField.string("hfa.register.subscriber_number", "Subscriber Number", FT_STRING)
p_hfa_register.fields.ip_address = ProtoField.string("hfa.register.ip_address", "IP-Address", FT_STRING)

function p_hfa_register.dissector(buf, pinfo, root)
	pinfo.cols["info"] = "Register"
	local i = 0
	while i < buf:len() do
		local item_type = buf(i, 1):uint()
		local item_len = buf(i + 1, 2):uint()

		local item = root:add(p_hfa_register.fields.information_element, buf(i, item_len + 3), item_type)
		item:add(p_hfa_register.fields.information_element_length, buf(i + 1, 2))
		if item_type == 0x01 then -- Device IP-Address
			item:append_text(" (Device IP-Address)")
			item:add(p_hfa_register.fields.ip_address, buf(i + 4, item_len - 1))
		elseif item_type == 0x72 then -- Subscriber Number
			item:append_text(" (Subscriber Number)")
			item:add(p_hfa_register.fields.subscriber_number, buf(i + 4, item_len - 1))
			pinfo.cols["info"] = "Register " .. buf(i + 4, item_len - 1):string()
		elseif item_type == 0x7f then -- MAC-Address
			item:append_text(" (MAC-Address)")
			item:add(p_hfa_register.fields.mac_address, buf(i + 3, item_len))
		else
			item:add_expert_info(PI_UNDECODED, PI_WARN, "Unknown Item Type")
		end
		i = i + item_len + 3
	end
end

p_request_part_number = Proto("request_part_number", "Part Number")
p_request_part_number.fields.partnumber = ProtoField.string("hfa.part_number.partnumber", "Part Number", FT_STRING)

function p_request_part_number.dissector(buf, pinfo, root)
	root:add(p_request_part_number.fields.partnumber, buf(0))
	pinfo.cols['info'] = "Part Number " .. buf(0):string()
end

function toBits(num,bits)
    -- returns a table of bits, most significant first.
    bits = bits or select(2,math.frexp(num))
    local t={} -- will contain the bits        
    for b=bits,1,-1 do
        t[b]=math.fmod(num,2)
        num=(num-t[b])/2
    end
    return t
end