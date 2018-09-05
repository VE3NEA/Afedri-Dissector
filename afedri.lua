----------------------------------------------------------------------------------------------------
--                   WireShark dissector for the Aftedri SDR radio protocol
----------------------------------------------------------------------------------------------------

-- Copyright (c) 2018 Alex Shovkoplyas VE3NEA


-- to install the dissector, just put this file in the WireShark plugins folder,
-- e.g., C:\Program Files (x86)\Wireshark\plugins\2.4.1




----------------------------------------------------------------------------------------------------
--                                        dissector
----------------------------------------------------------------------------------------------------
afedri_udp_protocol = Proto("Afedri-IQ",  "Afedri UDP Data Protocol")
afedri_tcp_protocol = Proto("Afedri",  "Afedri TCP Control Protocol")


function afedri_udp_protocol.dissector(buffer, pinfo, tree)
    if buffer:len() < 4 then return end
    pinfo.cols.protocol = afedri_udp_protocol.name
    subtree = tree:add(afedri_udp_protocol, buffer(), "Afedri Protocol Data")
    UdpHeader.dissect(buffer(0, 2))
    Word.dissect(buffer(2, 2), "sequence number")
    IqSamples.dissect(buffer(4, buffer:len()-4))
end

function afedri_tcp_protocol.dissector(buffer, pinfo, tree)
  if buffer:len() < 4 then return end
  pinfo.cols.protocol = afedri_tcp_protocol.name
  subtree = tree:add(afedri_tcp_protocol, buffer(), "Afedri Protocol Data")

  --common to all formats
  local word =  buffer(0,2):le_uint()
  local message_size = bit32.extract(word, 0, 13)
  local message_type = bit32.extract(word, 13, 3)
  subtree:add(buffer(0,2), "message size: " .. message_size)
  subtree:add(buffer(1,1), "message type: " .. message_type .. " (" .. look_up(message_type, MessageTypes) .. ")")

  --net format
  if (message_type == SET_CONTROL_ITEM) or (message_type == REQUEST_CONTROL_ITEM) then
    pinfo.cols.protocol = afedri_tcp_protocol.name .. "-NET"
    dissect_net_message(buffer)

  --hid format
  elseif message_type == TCP_HID_PACKET then
    pinfo.cols.protocol = afedri_tcp_protocol.name .. "-HID"
    dissect_hid_message(buffer)
  end
end

function dissect_net_message(buffer)
    local control_item = ControlItem.dissect(buffer(2,2))

    if control_item == CI_FREQUENCY then
        Channel.dissect(buffer(4,1))
        Frequency.dissect(buffer(5,4))

    elseif control_item == CI_RECEIVER_STATE then
        ReceiverState.dissect(buffer(5,1))

    elseif control_item == CI_RF_GAIN then
        Channel.dissect(buffer(4,1))
        Gain.dissect(buffer(5,1))

    elseif control_item == CI_DDC_SAMPLE_RATE then
        Frequency.dissect(buffer(5,4), "sampling rate")

    elseif control_item == CI_SAMPLE_RATE_CALIBRATION then
        -- if len=4, no args
        if buffer:len() == 9 then Frequency.dissect(buffer(5,4), "clock rate") end

    elseif control_item == CI_DATA_PACKET_SIZE then
        PacketSize.dissect(buffer(4,1))

    else
        RawData.dissect(buffer(4, buffer:len()-4))
    end
end

function dissect_hid_message(buffer)
    local hid_command_type = HidCommandType.dissect(buffer(2,1))

    if (hid_command_type == HID_FREQUENCY_REPORT) or (hid_command_type == HID_FREQUENCY_REPLY) then
        Frequency.dissect(buffer(3,4))
        Channel.dissect(buffer(7,1))

    elseif  hid_command_type == HID_GENERIC_REPORT
      then dissect_hid_request(buffer, subtree)

    elseif  hid_command_type == HID_GENERIC_REPLY
      then dissect_hid_reply(buffer)
    end
end

function dissect_hid_request(buffer)
    local hid_command = HidCommand.dissect(buffer(3,1))
    local cmd = HidCommands[hid_command]
    local start_pos = 4

    if cmd ~= nil then
        if cmd.arg1 ~= nil then
            cmd.arg1.type.dissect(buffer(start_pos, cmd.arg1.type.length), cmd.arg1.label)
            start_pos = start_pos + cmd.arg1.type.length
        end
        if cmd.arg2 ~= nil then
            cmd.arg2.type.dissect(buffer(start_pos, cmd.arg2.type.length), cmd.arg2.label)
        end
    else
        RawData.dissect(buffer(start_pos, buffer:len()-start_pos))
    end
end

function dissect_hid_reply(buffer)
    local hid_command = HidCommand.dissect(buffer(3,1))
    local cmd = HidCommands[hid_command]

    if (cmd ~= nil) and (cmd.ret ~= nil) then
        cmd.ret.type.dissect(buffer(4, cmd.ret.type.length), cmd.ret.label)
    else
        DWord.dissect(buffer(4,4))
    end
end




----------------------------------------------------------------------------------------------------
--                                       readonly data
----------------------------------------------------------------------------------------------------

--parameter types

Gain = {length = 1}
Frequency = {length = 4}
IpAddress = {length = 4}
MacAddress = {length = 2}
ControlItem = {length = 2}
HidCommand = {length = 1}
HidCommandType = {length = 1}
OnOff = {length = 1}
Channel = {length = 1}
MultiChannelMode = {length = 1}
PacketSize = {length = 1}
ReceiverState = {length = 1}
InitStatus = {length = 1}
SdrModel = {length = 1}
Bits = {length = 1}
Char = {length = 1}
Byte = {length = 1}
Word = {length = 2}
DWord = {length = 4}
RawData = {length = 5}
IqSamples = {length = 4}
UdpHeader = {length = 2}


--constants

SET_CONTROL_ITEM = 0
REQUEST_CONTROL_ITEM = 1
TCP_HID_PACKET = 7

HID_MEMORY_READ_WRITE_REPORT = 1
HID_GENERIC_REPORT = 2
HID_FREQUENCY_REPORT = 3
HID_GENERIC_REPLY = 6
HID_FREQUENCY_REPLY = 7

CI_FREQUENCY = 0x0020
CI_RECEIVER_STATE = 0x0018
CI_RF_GAIN = 0x0038
CI_SAMPLE_RATE_CALIBRATION = 0x00B0
CI_DDC_SAMPLE_RATE = 0x00B8
CI_DATA_PACKET_SIZE = 0x00C4


--lookup tables

MessageTypes = {
    [SET_CONTROL_ITEM] = "SET_CONTROL_ITEM",
    [REQUEST_CONTROL_ITEM] = "REQUEST_CONTROL_ITEM",
    [TCP_HID_PACKET] = "TCP_HID_PACKET"
}

HidCommandTypes = {
    [HID_MEMORY_READ_WRITE_REPORT] = "HID_MEMORY_READ_WRITE_REPORT",
    [HID_GENERIC_REPORT] = "HID_GENERIC_REPORT",
    [HID_FREQUENCY_REPORT] = "HID_FREQUENCY_REPORT",
    [HID_GENERIC_REPLY] = "HID_GENERIC_REPLY",
    [HID_FREQUENCY_REPLY] = "HID_FREQUENCY_REPLY"
}

ControlItems = {
    [0x0001] = "CI_TARGET_NAME",
    [0x0002] = "CI_TARGET_SERIAL_NUMBER",
    [0x0003] = "CI_INTERFACE_VERSION",
    [0x0004] = "CI_HW_FW_VERSION",
    [0x0005] = "CI_STATUS_ERROR_CODE",
    [0x0009] = "CI_PRODUCT_ID",
    [0x0018] = "CI_RECEIVER_STATE",
    [0x0020] = "CI_FREQUENCY",
    [0x0038] = "CI_RF_GAIN",
    [0x0048] = "CI_AF_GAIN",
    [0x0044] = "CI_RF_FILTER_SELECT",
    [0x008A] = "CI_AD_MODES",
    [0x00B4] = "CI_INPUT_SYNC_MODES",
    [0x00B8] = "CI_DDC_SAMPLE_RATE",
    [0x00B0] = "CI_SAMPLE_RATE_CALIBRATION",  --read clock frequency
    [0x00D0] = "CI_CALIBRATION_DATA",
    [0x00B6] = "CI_PULSE_OUTPUT_MODE",
    [0x012A] = "CI_DA_OUTPUT_MODE",
    [0x00C4] = "CI_DATA_PACKET_SIZE",
    [0x00C5] = "CI_UDP_IP_PORT",
    [0x0200] = "CI_RS232_OPEN",
    [0x0201] = "CI_RS232_CLOSE"
}

UdpHeaders = {
    [0x8404] = "16-Bit data, large packet",
    [0x8204] = "16-Bit data, small packet",
    [0x85A4] = "24-Bit data, large packet",
    [0x8484] = "24-Bit data, small packet"
}

OnOffValues = {
    [0] = "OFF",
    [1] = "ON"
}

Channels = {
    [0] = "AFEDRI_CH1",
    [2] = "AFEDRI_CH2",
    [3] = "AFEDRI_CH3",
    [4] = "AFEDRI_CH4"
}

MultiChannelModes = {
    [0] = "DUAL_CHANNEL_MODE_OFF",
    [1] = "DIVERSITY_MODE",
    [2] = "DUAL_CHANNEL_MODE",
    [3] = "DIVERSITY_INTERNAL_ADD_MODE",
    [4] = "QUAD_DIVERSITY_MODE",
    [5] = "QUAD_CHANNEL_MODE"
}

SdrModels = {
    [0] = "'AFEDRI SDR-Net'",
    [1] = "'SDR-IP'",
    [2] = "'AFE822x SDR-Net'"
}

PacketSizes = {
   [0] = "Large, 1028 or 1444 bytes",
   [1] = "Small, 515 or 388 bytes"
}

ReceiverStates = {
    [1] = "RCV_STOP",
    [2] = "RCV_START"
}


--hid commands

HidCommands = {
    --only as return value in ACK message
    [3] = {name = "HID_FREQUENCY_REPORT"},
    --only SDR to PC
    [27] = {name = "HID_GENERIC_OVERLAOD_STATE"}, -- bug in mainwindow.cpp, return type unknown
    [28] = {name = "HID_GENERIC_ACK", ret = {type = HidCommand, label = "reply to"}},
    --no args
    [9]  = {name = "HID_GENERIC_VER_COMMAND", ret = {type = Word, label = "firmware version"}},
    [14] = {name = "HID_GENERIC_GET_SR_COMMAND", ret = {type = Frequency, label = "sampling rate"}},
    [15] = {name = "HID_GENERIC_GET_DIVERSITY_MODE", ret = {type = MultiChannelMode}},
    [16] = {name = "HID_GENERIC_GET_SDR_IP_ADDRESS", ret = {type = IpAddress}},
    [17] = {name = "HID_GENERIC_GET_SDR_IP_MASK", ret = {type = IpAddress, label = "IP mask"}},
    [18] = {name = "HID_GENERIC_GET_GATEWAY_IP_ADDRESS", ret = {type = IpAddress, label = "gateway IP address"}},
    [19] = {name = "HID_GENERIC_GET_DST_IP_ADDRESS", ret = {type = IpAddress, label = "DSP IP address"}},
    [20] = {name = "HID_GENERIC_GET_DST_PORT", ret = {type = Word, label="port"}},
    [29] = {name = "HID_GENERIC_GET_SERIAL_NUMBER_COMMAND", ret = {type = DWord, label="serial number"}},
    [32] = {name = "HID_GENERIC_GET_VCO_COMMAND", ret = {type = Word, label = "VCO voltage"}},
    [34] = {name = "HID_GENERIC_GET_GAIN_TABLE_COMMAND", ret = {type = Word, label = "gain table"}},
    [36] = {name = "HID_GENERIC_SYNC_WORD_COMMAND", ret = {type = DWord, label="sync word"}},
    [37] = {name = "HID_GENERIC_HW_CPLD_SN_COMMAND", ret = {type = DWord, label="HW/CPLD version"}},
    [38] = {name = "HID_GENERIC_IAP_COMMAND"}, --firmware upgrade
    [41] = {name = "HID_GENERIC_GET_BROADCAST_STATE_COMMAND", ret = {type = OnOff}},
    [43] = {name = "HID_GENERIC_GET_BYPASS_LPF_COMMAND", ret = {type = OnOff}},
    [51] = {name = "HID_GENERIC_GET_AFEDRI_ID_COMMAND", ret = {type = SdrModel}},
    [53] = {name = "HID_GENERIC_SOFT_RESET_COMMAND"},
    [54] = {name = "HID_GENERIC_GET_DHCP_STATE_COMMAND", ret = {type = OnOff}},
    [57] = {name = "HID_GENERIC_HW_CPLD2_SN_COMMAND", ret = {type = DWord, label="CPLD2 version"}},
    [63] = {name = "HID_GENERIC_GET_MAXIMUM_SR_COMMAND", ret = {type = Frequency, label = "sampling rate"}},
    [71] = {name = "HID_GENERIC_AGC_GET_STATE_COMMAND", ret = {type = Bits, label = "AGC on/off"}}, --todo: bit field
    [73] = {name = "HID_GENERIC_GET_MULTISTREAM_MODE", ret = {type = OnOff}},
    [76] = {name = "HID_GENERIC_GET_DHCP_CLIENT_STATE_COMMAND", ret = {type = OnOff}},
    [91] = {name = "HID_GENERIC_GET_R820T_REF_FREQ_COMMAND", ret = {type = Frequency}},
    [93] = {name = "HID_GENERIC_GET_MAC_COMMAND", ret = {type = MacAddress}},
    --boolean arg
    [11] = {name = "HID_GENERIC_HID_CONSOLE_ON", arg1 = {type = OnOff}},
    [26] = {name = "HID_GENERIC_START_UDP_STREAM_COMMAND", arg1 = {type = OnOff}},
    [40] = {name = "HID_GENERIC_BROADCAST_COMMAND", arg1 = {type = OnOff}},
    [42] = {name = "HID_GENERIC_BYPASS_LPF_COMMAND", arg1 = {type = OnOff}},
    [49] = {name = "HID_GENERIC_MULTICAST_COMMAND", arg1 = {type = OnOff}},
    [50] = {name = "HID_GENERIC_SET_AFEDRI_ID_COMMAND", arg1 = {type = SdrModel}},
    [52] = {name = "HID_GENERIC_SAVE_AFEDRI_ID_COMMAND", arg1 = {type = SdrModel}},
    [55] = {name = "HID_GENERIC_SET_DHCP_STATE_COMMAND", arg1 = {type = OnOff}},
    [72] = {name = "HID_GENERIC_SET_MULTISTREAM_MODE", arg1 = {type = MultiChannelMode}},
    [74] = {name = "HID_GENERIC_SAVE_MULTISTREAM_MODE", arg1 = {type = MultiChannelMode}},
    [75] = {name = "HID_SET_LED_ON_OFF", arg1 = {type = OnOff}},
    [77] = {name = "HID_GENERIC_SET_DHCP_CLIENT_STATE_COMMAND", arg1 = {type = OnOff}},
    [82] = {name = "HID_GENERIC_SET_R820T_LNA_AGC_COMMAND", arg1 = {type = OnOff}},
    [83] = {name = "HID_GENERIC_SET_R820T_MIXER_AGC_COMMAND", arg1 = {type = OnOff}},
    [87] = {name = "HID_GENERIC_SET_R820T_PWR_ON_COMMAND", arg1 = {type = OnOff}},
    --byte arg
    [1] = {name = "HID_GENERIC_GET_FREQ_COMMAND", arg1 = {type = Channel}, ret = {type = Frequency}},
    [10] = {name = "HID_GENERIC_CONSOLE_IO_COMMAND", arg1 = {type = Char}, ret = {type = Char}},
    [0x55] = {name = "HID_READ_EEPROM_COMMAND", arg1 = {type = Byte, label = "address"}, ret = {type = Word, label = "EEPROM data"}},
    [68] = {name = "HID_GENERIC_SET_USB_MODE", arg1 = {type = Byte, label = "mode"}},
    [69] = {name = "HID_GENERIC_SET_OVR_MODE", arg1 = {type = Bits, label = "AGC on/off"}}, --todo: bit field
    [70] = {name = "HID_GENERIC_AGC_LEVEL_COMMAND", arg1 = {type = Channel}},
    [79] = {name = "HID_GENERIC_SET_R820T_LNA_GAIN_COMMAND", arg1 = {type = Byte, label = "gain"}},  -- find out the format
    [80] = {name = "HID_GENERIC_SET_R820T_MIXER_GAIN_COMMAND", arg1 = {type = Byte, label = "gain"}},  -- find out the format
    [81] = {name = "HID_GENERIC_SET_R820T_VGA_GAIN_COMMAND", arg1 = {type = Byte, label = "gain"}},  -- find out the format
    [84] = {name = "HID_GENERIC_SET_R820T_IF_BW_COMMAND", arg1 = {type = Byte, label = "bandwidth"}},
    [88] = {name = "HID_GENERIC_SET_R820T_HIGHPASS_BW_COMMAND", arg1 = {type = Byte, label = "low cutoff"}},
    [89] = {name = "HID_GENERIC_SET_R820T_LOWPASS_BW_COMMAND", arg1 = {type = Byte, label = "high cutoff"}},
    --byte + byte
    [2] = {name = "HID_GENERIC_GAIN_COMMAND", arg1 = {type = Byte, label = "gain"}, arg2 = {type = Channel}}, -- for AFE822x should be 0
    [8] = {name = "HID_GENERIC_DAC_COMMAND", arg1 = {type = Gain}, arg2 = {type = Channel}}, -- rf gain, maps to dB
    [48] = {name = "HID_GENERIC_SET_MULTICHANNEL_COMMAND", arg1 = {type = MultiChannelMode}, arg2 = {type = Channel}},
    --word
    [31] = {name = "HID_GENERIC_SET_VCO_COMMAND", arg1 = {type = Word, label = "VCO voltage"}},            --(2048 + vco_voltage)
    [33] = {name = "HID_GENERIC_SAVE_GAIN_TABLE_COMMAND", arg1 = {type = Word, label = "gain table"}},    --(gain_table)
    [35] = {name = "HID_GENERIC_SET_BPF_COMMAND", arg1 = {type = Word}},            --(bpf_value)
    --byte + word
    [0x56] = {name = "HID_WRITE_EEPROM_COMMAND", arg1 = {type = Byte, label = "address"}, arg2 = {type = Word, label = "data"}},
    --word + byte
    [56] = {name = "HID_GENERIC_SET_PHASE_SHIFT_COMMAND", arg1 = {type = Word, label = "phase"}, arg2 = {type = Channel}},
    --word + word
    [39] = {name = "HID_GENERIC_WRITE_HWORD_TO_FLASH", arg1 = {type = Word, label = "address"}, arg2 = {type = Word, label = "data"}},
    --ip
    [21] = {name = "HID_GENERIC_SAVE_SDR_IP_ADDRESS", arg1 = {type = IpAddress, label = "IP address"}},
    [22] = {name = "HID_GENERIC_SAVE_SDR_IP_MASK", arg1 = {type = IpAddress, label = "IP mask"}},
    [23] = {name = "HID_GENERIC_SAVE_GATEWAY_IP_ADDRESS", arg1 = {type = IpAddress, label = "IP gateway"}},
    [24] = {name = "HID_GENERIC_SAVE_DST_IP_ADDRESS", arg1 = {type = Byte, IpAddress = "dst IP address"}},
    --dword
    [25] = {name = "HID_GENERIC_SAVE_DST_PORT", arg1 = {type = Word, label = "port"}}, --dword in mainwindow.cpp, should be word
    [92] = {name = "HID_GENERIC_SAVE_MAC_COMMAND", arg1 = {type = MacAddress}, ret = {type = MacAddress}},
    [30] = {name = "HID_GENERIC_SET_SAMPLE_RATE_COMMAND", arg1 = {type = Frequency, label = "sampling rate"}},
    [78] = {name = "HID_GENERIC_SET_R820T_FREQ_COMMAND", arg1 = {type = Frequency, label = "frequency"}},
    [90] = {name = "HID_GENERIC_SAVE_R820T_REF_FREQ_COMMAND", arg1 = {type = Frequency, label = "frequency"}},
    --inverted command
    [4] = {name = "HID_GENERIC_GET_INIT_STATUS_COMMAND", arg1 = {type = Byte, label = "inverted HID command"}, ret = {type = InitStatus}},
    [0xE1] = {name = "HID_GENERIC_INIT_FE_COMMAND", arg1 = {type = Byte, label = "inverted HID command"}},
    [12] = {name = "HID_GENERIC_SAVE_DEFAULT_PARAMS_COMMAND", arg1 = {type = Byte, label = "inverted HID command"}}


    --unused HID commands:
    --HID_GENERIC_I2C_SEND_COMMAND = 58
    --HID_GENERIC_I2C_READ_COMMAND = 59
    --HID_GENERIC_I2C_START_COND_COMMAND = 60
    --HID_GENERIC_I2C_STOP_COND_COMMAND = 61
    --HID_GENERIC_MULT_WRITE_JTAG_COMMAND = 62
    --HID_GENERIC_GET_MAIN_CLOCK_FREQ = 67
}




----------------------------------------------------------------------------------------------------
--                                   parameter dissectors
----------------------------------------------------------------------------------------------------
function Gain.dissect(data, label)
    if label == nil then label = "gain" end
    local byte = data:le_int()
    local gain = byte
    if gain > 0 then gain = gain * 3/8 - 10 end
    subtree:add(data, label .. ": " .. byte .. " (" .. gain .. " dB)")
end

function Frequency.dissect(data, label)
    if label == nil then label = "frequency" end
    subtree:add(data, label .. ": " .. comma_value(data:le_uint()) .. " Hz")
end

function IpAddress.dissect(data, label)
    if label == nil then label = "IP address" end
    local dword = data:le_uint()
    ip = data(3,1):uint() .. "." .. data(2,1):uint() .. "." .. data(1,1):uint() .. "." .. data(0,1):uint();
    subtree:add(data, label .. ": " .. ip)
end


function MacAddress.dissect(data, label)
    if label == nil then label = "MAC address" end
    local byte1 = data(0,1):le_uint()
    local byte2 = data(1,1):le_uint()
    mac = string.format("0x%04X (82:2A:%02X:%02X:%02X:%02X)", data:le_uint(), byte2, byte1, byte2, byte1)
    subtree:add(data, label .. ": " .. mac)
end

function InitStatus.dissect(data, label)
    if label == nil then label = "init status" end
    local value = data:le_uint()
    local str = "error"
    if value == 0 then str = "success" end
    subtree:add(data, label .. ": " .. value .. " (" .. str .. ")")
end

function ControlItem.dissect(data, label)
    return dissect_lookup(data, ControlItems, label, "control item")
end

function HidCommand.dissect(data, label)
    return dissect_lookup(data, HidCommands, label, "HID command")
end

function HidCommandType.dissect(data, label)
    return dissect_lookup(data, HidCommandTypes, label, "HID command type")
end

function OnOff.dissect(data, label)
    dissect_lookup(data, OnOffValues, label, "on/off")
end

function Channel.dissect(data, label)
    dissect_lookup(data, Channels, label, "channel")
end

function MultiChannelMode.dissect(data, label)
    dissect_lookup(data, MultiChannelModes, label, "mode")
end

function PacketSize.dissect(data, label)
    dissect_lookup(data, PacketSizes, label, "packet size")
end

function ReceiverState.dissect(data, label)
    dissect_lookup(data, ReceiverStates, label, "receiver state")
end

function SdrModel.dissect(data, label)
    dissect_lookup(data, SdrModels, label, "SDR model")
end

function Bits.dissect(data, label)
    if label == nil then label = "bits" end
    local value = data:le_uint()
    local str = ""
    for i=data:len() * 8 - 1, 0, -1 do str = str .. string.char(0x30 + bit32.extract(value, i, 1)) .. " " end
    subtree:add(data, label .. ": " .. str)
end

function Char.dissect(data, label)
    if label == nil then label = "char" end
    local byte = data:le_uint()
    subtree:add(data, label .. ": " .. string.format('%02X', byte) .. " ('" .. string.char(byte) .. "')")
end

function Byte.dissect(data, label)
    if label == nil then label = "8-bit value" end
    local byte = data:le_uint()
    subtree:add(data, label .. ": " .. byte .. " (0x" .. string.format('%02X', byte) .. ")")
end

function Word.dissect(data, label)
    if label == nil then label = "16-bit value" end
    local word = data:le_uint()
    subtree:add(data, label .. ": " .. word .. " (0x" .. string.format('%04X', word) .. ")")
end

function DWord.dissect(data, label)
    if label == nil then label = "32-bit value" end
    local dword = data:le_uint()
    subtree:add(data, label .. ": " .. dword .. " (0x" .. string.format('%08X', dword) .. ")")
end

function RawData.dissect(data, label)
    if data:len() == 0 then return end
    if label == nil then label = "raw data" end
    local str = ""
    local count = data:len()
    if count > 20 then count = 20 end
    for i = 0, count-1 do str = str .. string.format('%02X ', data(i,1):uint()) end
    if count < data:len() then str = str .. "..." end
    subtree:add(data, label .. ": " .. str)
end

function IqSamples.dissect(data, label)
    local byte_count = data:len()
    if byte_count < 4 then return end
    if label == nil then label = "I/Q data" end
    local str = "   "

    if (byte_count == 1028-4) or (byte_count == 515-4) then width = 2
    elseif (byte_count == 1444-4) or (byte_count == 388-4) then width = 3 end

    local sample_count = math.floor(byte_count / (2 * width))
    local node = subtree:add(data, label .. string.format(", %d 2x%d-bit samples", sample_count, width * 8))

    for i = 0, sample_count-1 do
        str = str .. "(" .. sample(data(i*2*width, width)) .. ", " .. sample(data(i*2*width+width, width)) .. ")"

        if (i % 4) == 3 then
            node:add(data((i-3)*2*width, 8 * width), str)
            str = "   "
            if i == 15 then node:add(data((i+1)*2*width, (sample_count-i-1) * 2 * width), "   ..."); break end
        end
    end

    if str ~= "   " then  node:add(data, str) end
end

function UdpHeader.dissect(data, label)
    if label == nil then label = "header" end
    local value = data:le_uint()
    local name = look_up(value, UdpHeaders)
    subtree:add(data, label .. ": " .. string.format('0x%04X', value) .. " (" .. name .. ")")
    return name ~= "Unknown"
end




----------------------------------------------------------------------------------------------------
--                                    helper functions
----------------------------------------------------------------------------------------------------
function look_up(value, table)
    local result = table[value]
    if type(result) == "table" then result = result.name end
    if result == nil then result = "Unknown" end
    return result
end

function dissect_lookup(data, table, label, default_label)
    if label == nil then label = default_label end
    local value = data:le_uint()
    local name = look_up(value, table)
    subtree:add(data, label .. ": " .. value .. " (" .. name .. ")")
    return value
end

--found on the Internet
function comma_value(value)
    local formatted = value
    local k = 0
    while true do
      formatted, k = string.gsub(formatted, "^(-?%d+)(%d%d%d)", '%1,%2')
      if k == 0 then break end
    end
    return formatted
  end

function sample(data)
    local v = data:le_int()

    --16-bit, dec format
    if data:len() == 2 then return string.format('%6d', v) end

    --24-bit, hex format, helps to see zero padding
    local str = string.format('+0x%06x', v)
    if bit.band(v, 0x800000) ~= 0 then  str = string.format('-0x%06x', 0x1000000 - v) end
    return str
end





----------------------------------------------------------------------------------------------------
--                                   register dissector
----------------------------------------------------------------------------------------------------
local tcp_port = DissectorTable.get("tcp.port")
tcp_port:add(50000, afedri_tcp_protocol)

local udp_port = DissectorTable.get("udp.port")
udp_port:add(50000, afedri_udp_protocol)