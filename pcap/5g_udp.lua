
    --   使用该脚本的方法：
    --   修改加载配置入口：C:\Program Files\Wireshark\init.lua
    --   在init.lua文件末尾加入一行, 
    --   dofile("E:/wireshark_lua/5g_udp.lua")
    --   "E:/wireshark_lua/5g_udp.lua" 为当前文件的路径

-- 定义协议名称和描述
local udp_proto_5g 		= Proto("udp_5g", "udp_header")
local eth_type_f 		= Field.new("eth.type")
local ip_proto_f 		= Field.new("ip.proto")
local udp_dissector 	= Dissector.get("udp")
local udp_payload_field = Field.new("udp.payload")

-- 定义协议字段
local f_packet_mark 	= ProtoField.uint32			("udp_5g.packet_mark"		, "Packet_mark"		, base.HEX)
local f_flag 			= ProtoField.uint8 			("udp_5g.flag"				, "Flag"			, base.HEX)
local f_message_len 	= ProtoField.uint16			("udp_5g.message_len"		, "Message_len"		, base.HEX)
local f_sequence_num 	= ProtoField.uint32			("udp_5g.sequence_num"		, "Sequence_num"	, base.HEX)
local f_isp_id 			= ProtoField.uint8 			("udp_5g.isp_id"			, "Isp_id"			, base.HEX)
local f_interface 		= ProtoField.uint8 			("udp_5g.interface"			, "Interface"		, base.HEX)
local f_rat_type 		= ProtoField.uint8 			("udp_5g.rat_type"			, "Rat_type"		, base.HEX)
local f_proceudre_type 	= ProtoField.uint8 			("udp_5g.proceudre_type"	, "Rroceudre_type"	, base.HEX)
local f_iot_flag 		= ProtoField.uint8 			("udp_5g.iot_flag"			, "Iot_flag"		, base.HEX)
local f_capture_time    = ProtoField.absolute_time	("udp_5g.capture_time"		, "Capture_time"	, base.UTC)
local f_front_device_id = ProtoField.uint8 			("udp_5g.front_device_id"	, "Front_device_id"	, base.HEX)
local f_city_id 		= ProtoField.uint16			("udp_5g.city_id"			, "City_id"			, base.HEX)
local f_imsi 			= ProtoField.uint64			("udp_5g.imsi"				, "Imsi"			, base.HEX)
local f_imei_esn_meid 	= ProtoField.uint64			("udp_5g.imei_esn_meid"		, "Imei_esn_meid"	, base.HEX)
local f_msisdn 			= ProtoField.uint64			("udp_5g.msisdn"			, "Msisdn"			, base.HEX)
local f_tai 			= ProtoField.uint64			("udp_5g.tai"				, "Tai"				, base.HEX)
local f_ncgi 			= ProtoField.uint64			("udp_5g.ncgi"				, "Ncgi"			, base.HEX)

local f_tlv_type        = ProtoField.uint8			("udp_5g.tlv.type"			, "Type"			, base.HEX)
local f_tlv_length      = ProtoField.uint8			("udp_5g.tlv.length"		, "Length"			, base.HEX)
local f_tlv_value       = ProtoField.bytes			("udp_5g.tlv.value"			, "Value")

local f_tlv_ntype       = ProtoField.uint8			("udp_5g.tlv.ntype"			, "nType"			, base.HEX)
local f_tlv_nlength     = ProtoField.uint8			("udp_5g.tlv.nlength"		, "nLength"			, base.HEX)
local f_tlv_nvalue      = ProtoField.bytes			("udp_5g.tlv.nvalue"		, "nValue")

local f_ipv4_addr    	= ProtoField.ipv4			("udp_5g.tlv.ipv4"			, "IPv4 Address")
local f_ipv6_addr    	= ProtoField.ipv6			("udp_5g.tlv.ipv6"			, "IPv6 Address")
local f_is_marked_time  = ProtoField.absolute_time	("udp_5g.tlv.marked_time"	, ".marked_time"	, base.UTC)
local f_mac_addr 		= ProtoField.ether			("udp_5g.tlv.mac"			,"MAC Address")
local f_tlv_special_val = ProtoField.uint32			("udp_5g.tlv.special_val"	, "Special Value"	, base.HEX) 

udp_proto_5g.fields = { f_packet_mark, 
					f_flag, 
					f_message_len, 
					f_sequence_num, 
					f_isp_id, 
					f_interface, 
					f_rat_type, 
					f_proceudre_type, 
					f_iot_flag, 
					f_capture_time, 
					f_front_device_id, 
					f_city_id, 
					f_imsi, 
					f_imei_esn_meid, 
					f_msisdn, 
					f_tai, 
					f_ncgi, 
					f_tlv_type, 
					f_tlv_length, 
					f_tlv_value,
					f_ipv4_addr,
					f_ipv6_addr,
					f_is_marked_time,
					f_mac_addr,
					f_tlv_ntype,
					f_tlv_nlength,
					f_tlv_nvalue,
					f_tlv_special_val}

-- 注册为后置解析器
register_postdissector(udp_proto_5g)

-- 主解析函数
function udp_proto_5g.dissector(buffer, pinfo, tree)
    -- 基本校验
    if buffer:len() < 65 then 
		return 
	end
    
    -- 获取协议字段值
    local eth_type 			= eth_type_f()
    local ip_proto 			= ip_proto_f()

    -- 验证协议条件
    if not (eth_type and eth_type.value == 0x0800) then 
		return 
	end  -- 仅处理IPv4
	
    if not (ip_proto and ip_proto.value == 17) then 
		return 
	end      -- 仅处理UDP
    
	local payload_range 	= udp_payload_field().range
    local payload_offset 	= payload_range:offset()
	
	local packet_mark_val = buffer(payload_offset, 4):uint()
    if packet_mark_val ~= 0x9a8b7c6d then
        return 
    end
	
	local timestamp_u64 = buffer(payload_offset + 16, 8):uint64()
	local timestamp_us = timestamp_u64:tonumber()
	
	local seconds = math.floor(timestamp_us / 1000000)
    local useconds = timestamp_us % 1000000
	
	local beijing_offset = 8 * 3600  -- 8 小时的秒数
	local seconds_beijing = seconds + beijing_offset
	
	local nstime_beijing  = NSTime.new(seconds_beijing, useconds * 1000)
	
    -- 添加到协议树

	
    -- 在协议树中添加自定义协议
    local subtree = tree:add(udp_proto_5g, buffer(), "Custom Protocol Payload")
    
    subtree:add(f_packet_mark, 		buffer(payload_offset + 0, 4))
    subtree:add(f_flag, 			buffer(payload_offset + 4, 1))
    subtree:add(f_message_len, 		buffer(payload_offset + 5, 2))
    subtree:add(f_sequence_num, 	buffer(payload_offset + 7, 4))
    subtree:add(f_isp_id, 			buffer(payload_offset + 11, 1))
    subtree:add(f_interface, 		buffer(payload_offset + 12, 1))
    subtree:add(f_rat_type, 		buffer(payload_offset + 13, 1))
    subtree:add(f_proceudre_type, 	buffer(payload_offset + 14, 1))
    subtree:add(f_iot_flag, 		buffer(payload_offset + 15, 1))
	
    subtree:add(f_capture_time, 	nstime_beijing)
	
    subtree:add(f_front_device_id, 	buffer(payload_offset + 24, 1))	
    subtree:add(f_city_id, 			buffer(payload_offset + 25, 2))	
    subtree:add(f_imsi, 			buffer(payload_offset + 27, 8))	
    subtree:add(f_imei_esn_meid, 	buffer(payload_offset + 35, 8))	
    subtree:add(f_msisdn, 			buffer(payload_offset + 43, 8))	
    subtree:add(f_tai, 				buffer(payload_offset + 51, 6))
    subtree:add(f_ncgi, 			buffer(payload_offset + 57, 8))
	
  -- 动态解析TLV部分（从65字节开始）
    local offset = payload_offset + 65
    while offset < buffer:len() do
        -- 检查剩余字节是否足够读取头部
        if buffer:len() - offset < 2 then
            subtree:add_proto_expert_info(expert_malformed, "Incomplete TLV header")
            break
        end

        -- 读取类型和长度
        local tlv_type = buffer(offset, 1):uint()
        local tlv_len = buffer(offset+1, 1):uint()
        
        -- 检查数据长度是否足够
        if buffer:len() - offset < (2 + tlv_len) then
            subtree:add_proto_expert_info(expert_malformed, string.format("TLV type 0x%02X truncated", tlv_type))
            break
        end

        -- 创建TLV子树
        local tlv_tree = subtree:add(udp_proto_5g, buffer(offset, 2 + tlv_len),
            string.format("TLV: Type=0x%02X, Length=%d", tlv_type, tlv_len))

        -- 添加字段到树
        tlv_tree:add(f_tlv_type, buffer(offset, 1))
        tlv_tree:add(f_tlv_length, buffer(offset+1, 1))
		
		if tlv_type == 0x02 or tlv_type == 0x03 then
			local type_desc = string.format("IP Info (Type=0x%02X)", tlv_type)
			local spec_tree = tlv_tree:add(udp_proto_5g, buffer(offset, 2 + tlv_len), type_desc)
					
			if tlv_len == 8 then
				spec_tree:add(f_ipv4_addr, buffer(offset+2, 4))
				spec_tree:add(f_tlv_value, buffer(offset+6, 4))
				:append_text(" [IPv4 + Value]")
			elseif tlv_len == 20 then
				spec_tree:add(f_ipv6_addr, buffer(offset+2, 16))
				spec_tree:add(f_tlv_value, buffer(offset+18, 4))
				:append_text(" [IPv6 + Value]")
			elseif tlv_len == 24 then
				spec_tree:add(f_ipv4_addr, buffer(offset+2, 4))
				spec_tree:add(f_ipv6_addr, buffer(offset+6, 16))
				spec_tree:add(f_tlv_value, buffer(offset+22, 4))
				:append_text(" [IPv4+IPv6 + Value]")
			else
				tlv_tree:add(f_tlv_value, buffer(offset+2, tlv_len))
			end	
			
        elseif tlv_type == 0x05 then
			local ntlv_type = buffer(offset+2, 1):uint()
			local ntlv_len  = buffer(offset+3, 1):uint()
			
			-- 创建TLV子树
			local ntlv_tree = subtree:add(tlv_tree, buffer(offset + 3, 2 + ntlv_len),
				string.format("nTLV: nType=0x%02X, nLength=%d", ntlv_type, ntlv_len))

			-- 添加字段到树
			ntlv_tree:add(f_tlv_ntype, buffer(offset + 2, 1))
			ntlv_tree:add(f_tlv_nlength, buffer(offset + 3, 1))
			
			local ntype_desc = string.format("IP Info (Type=0x%02X)", tlv_type)
			local nspec_tree = ntlv_tree:add(tlv_tree, buffer(offset + 3, 2 + ntlv_len), ntype_desc)
			
			if ntlv_len == 8 then
				nspec_tree:add(f_ipv4_addr, buffer(offset+4, 4))
				nspec_tree:add(f_tlv_value, buffer(offset+8, 4))
				:append_text(" [IPv4 + Value]")
			elseif ntlv_len == 20 then
				nspec_tree:add(f_ipv6_addr, buffer(offset+4, 16))
				nspec_tree:add(f_tlv_value, buffer(offset+10, 4))
				:append_text(" [IPv6 + Value]")
			elseif ntlv_len == 24 then
				nspec_tree:add(f_ipv4_addr, buffer(offset+4, 4))
				nspec_tree:add(f_ipv6_addr, buffer(offset+8, 16))
				nspec_tree:add(f_tlv_value, buffer(offset+24, 4))
				:append_text(" [IPv4+IPv6 + Value]")
			else
				tlv_tree:add(f_tlv_value, buffer(offset+4, tlv_len))
			end	
        elseif tlv_type == 0x07  or tlv_type == 0x0e or tlv_type == 0x10 then
			if tlv_len == 4 then
                tlv_tree:add(f_ipv4_addr, buffer(offset+2, 4))
            else
				tlv_tree:add(f_tlv_value, buffer(offset+2, tlv_len))
			end
		elseif tlv_type == 0x08  or tlv_type == 0x0f or tlv_type == 0x11 then
			if tlv_len == 16 then
                tlv_tree:add(f_ipv6_addr, buffer(offset+2, 16))
            else
				tlv_tree:add(f_tlv_value, buffer(offset+2, tlv_len))
			end
		elseif tlv_type == 0x12 then
			if tlv_len == 8 then
				timestamp_u64 	= buffer(offset+2, 8):uint64()
				timestamp_us 	= timestamp_u64:tonumber()
				seconds 		= math.floor(timestamp_us / 1000000)
				useconds 		= timestamp_us % 1000000
				seconds_beijing = seconds + beijing_offset
				nstime_beijing  = NSTime.new(seconds_beijing, useconds * 1000)
				
                tlv_tree:add(f_is_marked_time, nstime_beijing)
            else
				tlv_tree:add(f_tlv_value, buffer(offset+2, tlv_len))
			end
		elseif tlv_type == 0x13 then
			if tlv_len == 6 then
                tlv_tree:add(f_mac_addr, buffer(offset+2, 8))
            else
				tlv_tree:add(f_tlv_value, buffer(offset+2, tlv_len))
			end
		else
			tlv_tree:add(f_tlv_value, buffer(offset+2, tlv_len))
		end

        offset = offset + 2 + tlv_len  -- 移动到下一个TLV
    end
end
