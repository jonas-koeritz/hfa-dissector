p_hfa = Proto("hfa", "HFA")

p_hfa.prefs["tcp_port"] = Pref.uint("TCP Port", 4060, "HFA TCP Port")

local f_length = ProtoField.uint16("hfa.length", "Message Length", base.DEC)
local f_msgtype = ProtoField.uint8("hfa.msgtype", "Message Type", base.HEX)

p_hfa.fields = { f_length, f_msgtype }

local msg_types = {
	[0x20] = { "hfa_request", "Request" },
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
	if buf:len() > 0 then
		root:add(p_alive_request.fields.timestamp, buf(6, 4))
	end
	pinfo.cols['info'] = "Alive Request"
end

p_alive_response = Proto("hfa_alive_response", "Alive Response")

function p_alive_response.dissector(buf, pinfo, root)
	pinfo.cols['info'] = "Alive Response"
end

p_request = Proto("hfa_request", "Request")

p_request.fields.request_type = ProtoField.uint8("hfa.request.type", "Request Type", base.HEX)

local request_types = {
	[0x40] = { "Key Control", "request_key" },
	[0x41] = { "Hookswitch Off-Hook"},
	[0x42] = { "Hookswitch On-Hook"},
	[0x43] = { "Set Display", "request_set_display" },
	[0x45] = { "Ringer", "request_ringer" },
	[0x54] = { "Set Audio", "request_set_audio" },
	[0x5b] = { "Set Ringer Volume", "request_set_ringer_volume" }
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
	pinfo.cols['info'] = "Set Audio [volume=" .. ((buf(1, 1):uint() % 0x10) + 1) .. ", microphone=" .. VALS_MIC_MUTE[buf(0, 1):uint()] .. "]"
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