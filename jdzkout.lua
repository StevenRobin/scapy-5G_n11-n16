-- @brief jdzk_out Protocol dissector plugin
-- @author zzq
-- @date 2015.08.12

-- create a new dissector
local NAME = "jdzk_out"
local jdzk_out = Proto(NAME, "JDZK_OUT")

-- create fields of jdzk_out_mac
local macfields = jdzk_out.fields
macfields.userid = ProtoField.uint8 (NAME .. ".userid", "UserId")
macfields.devid = ProtoField.uint8 (NAME .. ".devid", "Devid")
macfields.slot = ProtoField.uint8(NAME .. ".slot", "Slot")
macfields.card = ProtoField.uint8(NAME .. ".card", "Card")
macfields.inter = ProtoField.uint8(NAME .. ".inter", "Inter")
macfields.updown = ProtoField.string(NAME .. ".updown", "UpDown")
macfields.error = ProtoField.uint8(NAME .. ".error", "ERROR")

-- create fields of jdzk_out_payload
local payfields = jdzk_out.fields
payfields.smark = ProtoField.uint8 (NAME .. ".smark", "SMark")
----循环使用变量
payfields.usertype = ProtoField.uint8 (NAME .. ".usertype", "UserType")
payfields.userlen = ProtoField.uint8(NAME .. ".userlen", " -Userlen")
payfields.usercon = ProtoField.uint8(NAME .. ".usercon", "UserCon")
	payfields.appid = ProtoField.uint8(NAME .. ".appid", " -AppId")
	payfields.applen = ProtoField.uint8(NAME .. ".applen", " -AppLen")
	payfields.appcon = ProtoField.uint8(NAME .. ".appcon", " -AppCon")
	payfields.protoid = ProtoField.uint8(NAME .. ".protoid", " -ProtoId")
	payfields.protolen = ProtoField.uint8(NAME .. ".protolen", " -ProtoLen")
	payfields.protocon = ProtoField.uint8(NAME .. ".protocon", " -ProtoCon")
payfields.ruleid = ProtoField.uint8(NAME .. ".ruleid", " -RuleID")
payfields.adsl = ProtoField.string(NAME .. ".adsl", " -ADSL")
payfields.direction = ProtoField.uint8(NAME .. ".direction", " -Direction")
payfields.BSID = ProtoField.bytes(NAME .. ".BSID", " -BSID")
payfields.ECGI = ProtoField.bytes(NAME .. ".ECGI", " -ECGI")
payfields.TAI = ProtoField.bytes(NAME .. ".TAI", " -TAI")
payfields.RAI = ProtoField.bytes(NAME .. ".RAI", " -RAI")
payfields.SAI = ProtoField.bytes(NAME .. ".SAI", " -SAI")
payfields.CGI = ProtoField.bytes(NAME .. ".CGI", " -CGI")
payfields.APN = ProtoField.string(NAME .. ".APN", " -APN")
payfields.ESN = ProtoField.bytes(NAME .. ".ESN", " -ESN")
payfields.MEID = ProtoField.bytes(NAME .. ".MEID", " -MEID")
payfields.IMEI = ProtoField.bytes(NAME .. ".IMEI", " -IMEI")
payfields.MSISDN = ProtoField.bytes(NAME .. ".MSISDN", " -MSISDN")
payfields.IMSI = ProtoField.bytes(NAME .. ".IMSI", " -IMSI")

----循环使用变量
payfields.dmark = ProtoField.uint8(NAME .. ".dmark", "Dmark")
payfields.error = ProtoField.string(NAME .. ".error", "ERROR")


Dissector.get("data")



local function bin2hex(s)
	
	s=string.format ("%02X",string.byte(s))
	return s
end

	
-- dissect packet
function jdzk_out.dissector (buf, pinfo, tree)
	
--	subtree
--		mactree
--			submactree
--		paytree
--			subpaytree

	local endpos = buf:len()-4
	local begpos = buf:len()-8
		
	if((buf(endpos,4):uint() ~= 0x4a445a4b)) then

		return
		
	end

	while (begpos > 0)
	do
		if((buf(begpos,4):uint()==0x4a445a4b)) then
			
			break
			
		end
	
		begpos=begpos - 1

	end

	local subtree = tree:add(jdzk_out, buf())

---------   SMAC的信息携带功能开始
---------   SMAC的信息携带是从右向左的顺序
	
	offset=6

	local mactree = subtree:add(jdzk_out, buf(offset, 6))
	local userid = buf(offset+5, 1)
	mactree:add(payfields.userid, userid)
	mactree:append_text(", UserID: " .. userid:uint())

	local devid = buf(offset+4, 1)
	mactree:add(payfields.devid, devid)
	mactree:append_text(", DevID: " .. devid:uint())

	mactree:add(payfields.slot, buf(offset+3, 1))
	
	local card_tmp=buf(offset+2, 1)
	local card=bit.band (card_tmp:uint(), 0x0F)
	mactree:add(payfields.card, card)
	
	local inter0=buf(offset+1, 2)
	local inter=bit.rshift(bit.band (inter0:uint(), 0xFFF0),4)
	mactree:add(payfields.inter, inter)

	local updown_tmp=buf(offset, 1)
	if( updown_tmp:uint() == 0x00) then
		mactree:add(payfields.updown, "Unknow")
	elseif( updown_tmp:uint() == 0x02) then
		mactree:add(payfields.updown, "UP")
	elseif( updown_tmp:uint() == 0x04) then
		mactree:add(payfields.updown, "DOWN")
	else
		mactree:add(payfields.updown, "Error")
	end
	
---------   SMAC的信息携带功能完成
	
---------   payload中增加的jdzk标签信息开始
	
	local paytree = subtree:add(jdzk_out, buf(begpos,endpos-begpos+4))
	
	begpos = begpos + 4
	
	while(begpos < endpos)
	do
		local usertype= buf(begpos, 2)
		paytree:add(payfields.usertype, usertype)
--		paytree:append_text(", UserType: " .. usertype:uint())
		begpos = begpos + 2

		local userlen= buf(begpos, 2)
		paytree:add(payfields.userlen, userlen)
		begpos = begpos + 2
		
		if( usertype:uint() == 0x10) then
		
			paytree:add(payfields.appid, buf(begpos, 2))
			begpos = begpos + 2
			
			paytree:add(payfields.applen, buf(begpos, 2))
			begpos = begpos + 2
			
			local appcon= buf(begpos, 4)
			paytree:add(payfields.appcon, appcon)
			paytree:append_text(", AppCon: " .. appcon:uint())
			begpos = begpos + 4
			
			paytree:add(payfields.protoid, buf(begpos, 2))
			begpos = begpos + 2

			paytree:add(payfields.protolen, buf(begpos, 2))
			begpos = begpos + 2

			local protocon= buf(begpos, 4)
			paytree:add(payfields.protocon, protocon)
			paytree:append_text(", ProtoCon: " .. protocon:uint())
			begpos = begpos + 4
			
		elseif( usertype:uint() == 0x0f) then

			local ruleid = buf(begpos, userlen:uint())
			paytree:add(payfields.ruleid, ruleid)
			paytree:append_text(", RuleID: " .. ruleid:uint())
			begpos = begpos + userlen:uint()
		
		elseif( usertype:uint() == 0x0e) then

			local direction = buf(begpos, userlen:uint())
			paytree:add(payfields.direction, direction)
			paytree:append_text(", Direction: " .. direction)
			begpos = begpos + userlen:uint()

		elseif( usertype:uint() == 0x0c) then

			local BSID = buf(begpos, userlen:uint())
			paytree:add(payfields.BSID, BSID)
			paytree:append_text(", BSID: " .. BSID)
			begpos = begpos + userlen:uint()
			
		elseif( usertype:uint() == 0x0b) then

			local ECGI = buf(begpos, userlen:uint())
			paytree:add(payfields.ECGI, ECGI)
			paytree:append_text(", ECGI: " .. ECGI)
			begpos = begpos + userlen:uint()
			
		elseif( usertype:uint() == 0x0a) then

			local TAI = buf(begpos, userlen:uint())
			paytree:add(payfields.TAI, TAI)
			paytree:append_text(", TAI: " .. TAI)
			begpos = begpos + userlen:uint()
			
		elseif( usertype:uint() == 0x09) then

			local RAI = buf(begpos, userlen:uint())
			paytree:add(payfields.RAI, RAI)
			paytree:append_text(", RAI: " .. RAI)
			begpos = begpos + userlen:uint()
			
		elseif( usertype:uint() == 0x08) then

			local SAI = buf(begpos, userlen:uint())
			paytree:add(payfields.SAI, SAI)
			paytree:append_text(", SAI: " .. SAI)
			begpos = begpos + userlen:uint()
			
		elseif( usertype:uint() == 0x07) then

			local CGI = buf(begpos, userlen:uint())
			paytree:add(payfields.CGI, CGI)
			paytree:append_text(", CGI: " .. CGI)
			begpos = begpos + userlen:uint()
			
		elseif( usertype:uint() == 0x06) then

			local APN = buf(begpos, userlen:uint())
			paytree:add(payfields.APN, APN)
			paytree:append_text(", APN: " .. APN:string())
			begpos = begpos + userlen:uint()
			
		elseif( usertype:uint() == 0x05) then

			local ESN = buf(begpos, userlen:uint())
			paytree:add(payfields.ESN, ESN)
			paytree:append_text(", ESN: " .. ESN)
			begpos = begpos + userlen:uint()
			
		elseif( usertype:uint() == 0x04) then

			local MEID = buf(begpos, userlen:uint())
			paytree:add(payfields.MEID, MEID)
			paytree:append_text(", MEID: " .. MEID)
			begpos = begpos + userlen:uint()
			
		elseif( usertype:uint() == 0x03) then

			local IMEI = buf(begpos, userlen:uint())
			paytree:add(payfields.IMEI, IMEI)
			paytree:append_text(", IMEI: " .. IMEI)
			begpos = begpos + userlen:uint()
			
		elseif( usertype:uint() == 0x02) then

			local MSISDN = buf(begpos, userlen:uint())
			paytree:add(payfields.MSISDN, MSISDN)
			paytree:append_text(", MSISDN: " .. MSISDN)
			begpos = begpos + userlen:uint()
			
		elseif( usertype:uint() == 0x01) then

			local IMSI = buf(begpos, userlen:uint())
			paytree:add(payfields.IMSI, IMSI)
			paytree:append_text(", IMSI: " .. IMSI)
			begpos = begpos + userlen:uint()

		elseif( usertype:uint() == 0x00) then

			local adsl = buf(begpos, userlen:uint())
			paytree:add(payfields.adsl, adsl)
			paytree:append_text(", ADSL: " .. adsl:string())
			begpos = begpos + userlen:uint()
		else	
			local usercon = buf(begpos, userlen:uint())
			paytree:add(payfields.usercon, usercon)
			begpos = begpos + userlen:uint()
		
		
		end
		
	end

--		if( buf:len() ~= begpos) then
--
--			paytree:add(payfields.error, "error")
--
--		end

---------   payload中增加的jdzk标签信息完成
		
end
	

	
-- register this dissector
register_postdissector(jdzk_out)

