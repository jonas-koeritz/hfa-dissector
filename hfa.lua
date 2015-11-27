p_hfa = Proto("hfa", "HFA")

p_hfa.prefs["tcp_port"] = Pref.uint("TCP Port", 4060, "HFA TCP Port")

local f_length = ProtoField.uint16("hfa.length", "Message Length", base.DEC)
local f_msgtype = ProtoField.uint8("hfa.msgtype", "Message Type", base.HEX)

p_hfa.fields = { f_length, f_msgtype }

local msg_types = {
	[0x04] = { "hfa_register", "Register" },
	[0x06] = { "hfa_register_response", "Register Response" },
	[0x07] = { "hfa_register_decline", "Register Decline" },
	[0x20] = { "hfa_request", "Stimulus Request" },
	[0x28] = { "hfa_alive_request", "Alive Request" },
	[0x2a] = { 'hfa_alive_response', "Alive Response" },
	[0x30] = { 'hfa_codec_capabilities', "Codec Capabilities" },
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
		pinfo.cols['info'] = "Alive Request (Status Message)"
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
	[0x47] = { "Set Contrast", "request_set_contrast" },
	[0x48] = { "Show Clock", "request_show_clock" },
	[0x49] = { "Hide Clock", "request_hide_clock" },
	[0x4a] = { "Set Time Format", "request_set_time_format" },
	[0x54] = { "Set Audio", "request_set_audio" },
	[0x55] = { "Start Ringer", "request_start_ringer" },
	[0x56] = { "Stop Ringer" },
	[0x58] = { "Start Tone-Generation", "request_start_tone" },
	[0x59] = { "Stop Tone-Generation" },
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
	local row = buf(0, 1):uint()
	local col = buf(1, 1):uint()
	root:add(p_set_display.fields.display_row, buf(0, 1))
	root:add(p_set_display.fields.display_col, buf(1, 1))
	root:add(p_set_display.fields.display_content, buf(3), "\"" .. buf(3):string() .. "\"")
	pinfo.cols['info'] = "Set Display [row=" .. row .. ", col=" .. col .. "]: " .. buf(3):string()
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

p_show_clock = Proto("request_show_clock", "Show Clock")
p_show_clock.fields.row = ProtoField.uint8("hfa.clock.row", "Row", base.DEC)
p_show_clock.fields.col = ProtoField.uint8("hfa.clock.col", "Column", base.DEC)
p_show_clock.fields.id = ProtoField.uint8("hfa.clock.id", "ID", base.HEX)


function p_show_clock.dissector(buf, pinfo, root)
	local row = buf(0, 1):uint()
	local col = buf(1, 1):uint()
	pinfo.cols['info'] = "Show Clock [row=" .. row .. ", col=" .. col .. "]"
	root:add(p_show_clock.fields.row, buf(0, 1), row)
	root:add(p_show_clock.fields.col, buf(1, 1), col)
	root:add(p_show_clock.fields.id, buf(2, 1))
end

p_hide_clock = Proto("request_hide_clock", "Hide Clock")
p_hide_clock.fields.id = ProtoField.uint8("hfa.clock.id", "ID", base.HEX)

function p_hide_clock.dissector(buf, pinfo, root)
	root:add(p_hide_clock.fields.id, buf(0, 1))
end



local VALS_24H = {
	[0x01] = "12 Hours",
	[0x02] = "24 Hours"	
};


p_set_time_format = Proto("request_set_time_format", "Set Time Format")
p_set_time_format.fields.twentyfourhours = ProtoField.uint8("hfa.time_format.twentyfourhours", "24h Format", base.HEX, VALS_24H)
function p_set_time_format.dissector(buf, pinfo, root)
	root:add(p_set_time_format.fields.twentyfourhours, buf(0, 1))
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

local VALS_TON = {
	[0x91] = "E.164 International, ISDN/telephony numbering plan",
	[0x81] = "Unknown, ISDN/telephony numbering plan"
}

p_hfa_register = Proto("hfa_register", "Register")
p_hfa_register.fields.information_element = ProtoField.uint8("hfa.register.information_element", "Information Element", base.HEX)
p_hfa_register.fields.information_element_length = ProtoField.uint16("hfa.register.information_element.length", "Length")
p_hfa_register.fields.mac_address = ProtoField.bytes("hfa.register.mac_address", "MAC-Address")
p_hfa_register.fields.subscriber_ton = ProtoField.uint8("hfa.register.subscriber_ton", "Type of Number", base.HEX, VALS_TON)
p_hfa_register.fields.subscriber_number = ProtoField.string("hfa.register.subscriber_number", "Subscriber Number", FT_STRING)
p_hfa_register.fields.ip_address = ProtoField.string("hfa.register.ip_address", "IP-Address", FT_STRING)
p_hfa_register.fields.timestamp = ProtoField.absolute_time("hfa.register.timestamp", "Timestamp", FT_ABSOLUTE_TIME)
p_hfa_register.fields.pw_hash = ProtoField.bytes("hfa.register.pw_hash", "Password Hash")
p_hfa_register.fields.client_version = ProtoField.string("hfa.register.client_version", "Client Version", FT_STRING)

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
			item:add(p_hfa_register.fields.subscriber_ton, buf(i + 3, 1))
			item:add(p_hfa_register.fields.subscriber_number, buf(i + 4, item_len - 1))
			pinfo.cols["info"] = "Register " .. buf(i + 4, item_len - 1):string()
		elseif item_type == 0x7f then -- MAC-Address
			item:append_text(" (MAC-Address)")
			item:add(p_hfa_register.fields.mac_address, buf(i + 3, item_len))
		elseif item_type == 0x0e then -- Registration Data
			item:append_text(" (Registration Data)")
			item:add(p_hfa_register.fields.timestamp, buf(i + 33, 4))
			item:add(p_hfa_register.fields.pw_hash, buf(i + 41, 20))
			item:add(p_hfa_register.fields.client_version, buf(i + 61, item_len - 58))
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

p_set_contrast = Proto("request_set_contrast", "Set Contrast")
p_set_contrast.fields.display_contrast = ProtoField.uint8("hfa.set_contrast.display_contrast", "Display Contrast", base.HEX)
p_set_contrast.fields.keys_contrast = ProtoField.uint8("hfa.set_contrast.keys_contrast", "Keys Contrast", base.HEX)

function p_set_contrast.dissector(buf, pinfo, root)
	local display_contrast = buf(0, 1):uint() + 1
	local keys_contrast = buf(1, 1):uint() + 1

	root:add(p_set_contrast.fields.display_contrast, buf(0, 1), display_contrast)
	root:add(p_set_contrast.fields.keys_contrast, buf(1, 1), keys_contrast)

	pinfo.cols['info'] = "Set Contrast: display=" .. display_contrast .. ", keys=" .. keys_contrast
end


local VALS_MODE = {
	[0x00] = "F1 - F1 - F1",
	[0x01] = "F1+F2 - F1+F2 - F1+F2",
	[0x10] = "F1 - F2 - F3",
	[0x11] = "F1 - F2+F3 - F1"
}

local VALS_LOOP = {
	[0x00] = "Single-Shot",
	[0x01] = "Loop"	
}

local VALS_VOLUME = {
	[0x0D] = "Damping 0",
	[0x0A] = "Damping 1",
	[0x07] = "Damping 2",
	[0x10] = "Damping 3"
}

p_request_start_tone = Proto("request_start_tone", "Start Tone-Generation")
p_request_start_tone.fields.flags = ProtoField.uint8("hfa.tone_generator.flags", "Flags", base.HEX)
p_request_start_tone.fields.mode = ProtoField.uint8("hfa.tone_generator.flags.mode", "Mode", base.HEX, VALS_MODE, 0xC0, "Mode")
p_request_start_tone.fields.loop = ProtoField.uint8("hfa.tone_generator.flags.loop", "Loop", base.HEX, VALS_LOOP, 0x20, "Loop")
p_request_start_tone.fields.volume = ProtoField.uint8("hfa.tone_generator.volume", "Volume", base.DEC, VALS_VOLUME, 0x1F, "Volume")

p_request_start_tone.fields.frequencies = ProtoField.string("hfa.tone_generator.frequencies", "Frequencies", FT_STRING)
p_request_start_tone.fields.freq1 = ProtoField.uint8("hfa.tone_generator.freq1", "Frequency 1 (Hz)", base.DEC)
p_request_start_tone.fields.freq2 = ProtoField.uint8("hfa.tone_generator.freq2", "Frequency 2 (Hz)", base.DEC)
p_request_start_tone.fields.freq3 = ProtoField.uint8("hfa.tone_generator.freq3", "Frequency 3 (Hz)", base.DEC)

p_request_start_tone.fields.pulses = ProtoField.string("hfa.tone_generator.pulses", "Pulses", FT_STRING)
p_request_start_tone.fields.pulse1 = ProtoField.uint8("hfa.tone_generator.pulse1", "Pulse 1 (ms)", base.DEC)
p_request_start_tone.fields.pause1 = ProtoField.uint8("hfa.tone_generator.pause1", "Pause 1 (ms)", base.DEC)
p_request_start_tone.fields.pulse2 = ProtoField.uint8("hfa.tone_generator.pulse2", "Pulse 2 (ms)", base.DEC)
p_request_start_tone.fields.pause2 = ProtoField.uint8("hfa.tone_generator.pause2", "Pause 2 (ms)", base.DEC)
p_request_start_tone.fields.pulse3 = ProtoField.uint8("hfa.tone_generator.pulse3", "Pulse 3 (ms)", base.DEC)
p_request_start_tone.fields.pause3 = ProtoField.uint8("hfa.tone_generator.pause3", "Pause 3 (ms)", base.DEC)


function p_request_start_tone.dissector(buf, pinfo, root)
	local flags = root:add(p_request_start_tone.fields.flags, buf(0, 1))
	flags:add(p_request_start_tone.fields.mode, buf(0, 1))
	flags:add(p_request_start_tone.fields.loop, buf(0, 1))
	flags:add(p_request_start_tone.fields.volume, buf(0, 1))

	local frequencies = root:add(p_request_start_tone.fields.frequencies, buf(1, 3), "Frequencies")
	local f1 = frequencies:add(p_request_start_tone.fields.freq1, buf(1, 1), buf(1, 1):uint() * 60)
	f1:append_text(" (Approximation)")
	local f2 = frequencies:add(p_request_start_tone.fields.freq2, buf(2, 1), buf(2, 1):uint() * 60)
	f2:append_text(" (Approximation)")
	local f3 = frequencies:add(p_request_start_tone.fields.freq3, buf(3, 1), buf(3, 1):uint() * 60)
	f3:append_text(" (Approximation)")

	local pulses = root:add(p_request_start_tone.fields.pulses, buf(4, buf:len() - 4), "Pulses")
	pulses:add(p_request_start_tone.fields.pulse1, buf(4, 1), buf(4, 1):uint() * 25)
	pulses:add(p_request_start_tone.fields.pause1, buf(5, 1), buf(5, 1):uint() * 25)

	if buf:len() > 7 then
		pulses:add(p_request_start_tone.fields.pulse2, buf(6, 1), buf(6, 1):uint() * 25)
		pulses:add(p_request_start_tone.fields.pause2, buf(7, 1), buf(7, 1):uint() * 25)
		pulses:add(p_request_start_tone.fields.pulse3, buf(8, 1), buf(8, 1):uint() * 25)
		pulses:add(p_request_start_tone.fields.pause3, buf(9, 1), buf(9, 1):uint() * 25)
	end
end

p_request_start_ringer = Proto("request_start_ringer", "Start Ringer")
p_request_start_ringer.fields.volume = ProtoField.uint8("hfa.ringer.volume", "Volume", base.DEC)
p_request_start_ringer.fields.sound = ProtoField.uint8("hfa.ringer.sound", "Sound", base.DEC)
p_request_start_ringer.fields.pulse1 = ProtoField.uint8("hfa.ringer.pulse1", "Pulse 1", base.DEC)
p_request_start_ringer.fields.pause1 = ProtoField.uint8("hfa.ringer.pause1", "Pause 1", base.DEC)
p_request_start_ringer.fields.pulse2 = ProtoField.uint8("hfa.ringer.pulse2", "Pulse 2", base.DEC)
p_request_start_ringer.fields.pause2 = ProtoField.uint8("hfa.ringer.pause2", "Pause 2", base.DEC)

function p_request_start_ringer.dissector(buf, pinfo, root)
	local volume = buf(0, 1):uint() - 0x90 + 1
	local sound = buf(1, 1):uint() - 0x30 + 1
	if volume > 0 and sound > 0 then
		root:add(p_request_start_ringer.fields.volume, buf(0, 1), buf(0, 1):uint() - 0x90 + 1)
		root:add(p_request_start_ringer.fields.sound, buf(1, 1), buf(1, 1):uint() - 0x30 + 1)
	else
		root:add(p_request_start_ringer.fields.volume, buf(0, 1), buf(0, 1):uint())
		root:add(p_request_start_ringer.fields.sound, buf(1, 1), buf(1, 1):uint())
		pinfo.cols['info'] = "Information Tone"
	end
	root:add(p_request_start_ringer.fields.pulse1, buf(2, 1), buf(2, 1):uint() * 50)
	root:add(p_request_start_ringer.fields.pause1, buf(3, 1), buf(3, 1):uint() * 50)
	if buf:len() > 4 then 
		root:add(p_request_start_ringer.fields.pulse2, buf(4, 1), buf(4, 1):uint() * 50)
		root:add(p_request_start_ringer.fields.pause2, buf(5, 1), buf(5, 1):uint() * 50)
	end
end


local VALS_SILENCE_SUPPRESSION = {
	[0x00] = "Off",
	[0x01] = "On"
}

local VALS_CODECS = {
	[0x00] = "PCMU (G.711 u-Law)",
	[0x08] = "PCMA (G.711 A-Law)",
	[0x09] = "G.722",
	[0x12] = "G.729",
}

p_codec_preferences = Proto("hfa_codec_capabilities", "Codec Capabilities")
p_codec_preferences.fields.codec = ProtoField.string("hfa.codec_capabilities.codec", "Codec")
p_codec_preferences.fields.length = ProtoField.uint16("hfa.codec_capabilities.length", "Length", base.DEC)
p_codec_preferences.fields.audio_codec = ProtoField.uint8("hfa.codec_capabilities.codec", "Codec", base.HEX, VALS_CODECS)
p_codec_preferences.fields.packet_size = ProtoField.uint8("hfa.codec_capabilities.packet_size", "Packet Size (ms)", base.DEC)
p_codec_preferences.fields.silence_supp = ProtoField.uint8("hfa.codec_capabilities.silence_supp", "Silence Suppression", base.HEX, VALS_SILENCE_SUPPRESSION, 0x01)

p_codec_preferences.fields.rtp_base = ProtoField.uint16("hfa.codec_capabilities.rtp_base", "RTP Base", base.DEC)
p_codec_preferences.fields.rtcp_port = ProtoField.uint16("hfa.codec_capabilities.rtcp_port", "RTCP Port", base.DEC)

p_codec_preferences.fields.local_address = ProtoField.string("hfa.codec_capabilities.local_address", "Local Address", FT_STRINGZ)

function p_codec_preferences.dissector(buf, pinfo, root)
	pinfo.cols['info'] = "Codec Capabilities"

	local i = 0
	while i < buf:len() do
		local length = buf(i + 1, 2):uint()
		local codec = root:add(p_codec_preferences.fields.codec, buf(i, length + 3), "Codec definition")

		codec:add(p_codec_preferences.fields.length, buf(i + 1, 2), length)

		codec:add(p_codec_preferences.fields.audio_codec, buf(i + 5, 1))

		codec:add(p_codec_preferences.fields.packet_size, buf(i + 7, 1))
		codec:add(p_codec_preferences.fields.silence_supp, buf(i + 8, 1))
		codec:add(p_codec_preferences.fields.rtp_base, buf(i + 9, 2))
		codec:add(p_codec_preferences.fields.rtcp_port, buf(i + 11, 2))
		codec:add(p_codec_preferences.fields.local_address, buf(i + 19, length - 16))
		i = i + length + 3
	end
end

p_register_response = Proto("hfa_register_response", "Register Response")
p_register_response.fields.parameter = ProtoField.uint8("hfa.register_response.parameter", "Parameter", base.HEX)
p_register_response.fields.param_length = ProtoField.uint16("hfa.register_response.param_length", "Length", base.DEC)
p_register_response.fields.param_value = ProtoField.bytes("hfa.register_response.param_value", "Value")

function p_register_response.dissector(buf, pinfo, root)
	pinfo.cols['info'] = "Register Response"
	local i = 0

	while i < buf:len() do
		local length = buf(i + 1, 2):uint()
		local param = root:add(p_register_response.fields.parameter, buf(i, length + 3), buf(i, 1):uint())
		param:add(p_register_response.fields.param_length, buf(i + 1, 2))

		param:add(p_register_response.fields.param_value, buf(i + 3, length))

		i = i + length + 3
	end
end

local VALS_REGISTER_DECLINE_CAUSE = {
};

p_register_decline = Proto("hfa_register_decline", "Register Decline")

p_register_decline.fields.cause = ProtoField.uint8("hfa.register_decline.cause", "Cause", base.HEX, VALS_REGISTER_DECLINE_CAUSE)
p_register_decline.fields.item = ProtoField.uint8("hfa.register_decline.item", "Item", base.HEX)
p_register_decline.fields.length = ProtoField.uint16("hfa.register_decline.length", "Length", base.DEC)

function p_register_decline.dissector(buf, pinfo, root)
	pinfo.cols['info'] = "Register Decline"
	local i = 0

	while i < buf:len() do
		local length = buf(i + 1, 2):uint()
		local item_type = buf(i, 1):uint()

		local item = root:add(p_register_decline.fields.item, buf(i, 1), item_type)
		if item_type == 0x08 then
			item:append_text(" (Cause)")
			item:add(p_register_decline.fields.length, buf(i + 1, 2))
			item:add(p_register_decline.fields.cause, buf(i + 3, 1), buf(i + 3, 1):uint())
		end
		i = i + length + 3
	end
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