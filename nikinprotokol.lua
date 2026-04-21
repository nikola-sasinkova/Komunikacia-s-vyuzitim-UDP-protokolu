nikinprotokol = Proto("NikinProtokol", "NikinProtokol porty: 65001/65002")

k_msg_type = ProtoField.string("nikinprotokol.msg_type", "Typ spravy")
k_seq_num = ProtoField.uint16("nikinprotokol.seq_num", "Sekvencne cislo spravy", base.HEX)
k_max_seq_num = ProtoField.uint32("nikinprotokol.seq_num", "Maximalne sekvencne cislo - pocet fragmentov, ktore budu prijate", base.HEX)
k_kseq_num = ProtoField.uint32("nikinprotokol.kseq_num", "Sekvencne cislo KEEP-ALIVE spravy", base.HEX)
k_mseq_num = ProtoField.uint32("nikinprotokol.mseq_num", "Sekvencne cislo fragmentu s textovou DATA spravou", base.HEX)
k_ack_num = ProtoField.uint16("nikinprotokol.ack_num", "Cislo ACK", base.HEX)
k_kack_num = ProtoField.uint32("nikinprotokol.kack_num", "KEEP-ALIVE ACK", base.HEX)
k_checksum = ProtoField.uint16("nikinprotokol.checksum", "Checksum fragmentu DATA textovej spravy", base.HEX)
k_ret_data = ProtoField.string("nikinprotokol.ret_data", "RET sprava")
k_payload = ProtoField.string("nikinprotokol.payload", "Payload spravy")

nikinprotokol.fields = { k_msg_type, k_seq_num, k_max_seq_num, k_kseq_num, k_mseq_num, k_ack_num, k_kack_num, k_checksum, k_ret_data, k_payload }

function nikinprotokol.dissector(buffer, pinfo, strom)
    pinfo.cols.protocol = nikinprotokol.name

    local podstrom = strom:add(nikinprotokol, buffer(), "Data")

    local msg_type = buffer(0, 1):string()
    local msg_type_item = podstrom:add(k_msg_type, buffer(0, 1))

    if msg_type == 's' then
		msg_type_item:append_text(" (" .. "SYN sprava" .. ")")
        local seq_num = buffer(1, 2):uint()
        podstrom:add(k_seq_num, buffer(1, 2)):append_text(" (" .. seq_num .. ")")
	end
	if msg_type == 'f' then
		msg_type_item:append_text(" (" .. "FIN sprava" .. ")")
        local seq_num = buffer(1, 2):uint()
        podstrom:add(k_seq_num, buffer(1, 2)):append_text(" (" .. seq_num .. ")")
	end
    if msg_type == 'a' then
		msg_type_item:append_text(" (" .. "ACK sprava" .. ")")
        local ack_num = buffer(1, 2):uint()
        podstrom:add(k_ack_num, buffer(1, 2)):append_text(" (" .. ack_num .. ")")
    end
	if msg_type == 'q' then
		msg_type_item:append_text(" (" .. "FIN-ACK sprava" .. ")")
        local ack_num = buffer(1, 2):uint()
        podstrom:add(k_ack_num, buffer(1, 2)):append_text(" (" .. ack_num .. ")")
    end
	if msg_type == 'w' then
		msg_type_item:append_text(" (" .. "3W sprava" .. ")")
        local seq_num = buffer(1, 2):uint()
        podstrom:add(k_seq_num, buffer(1, 2)):append_text(" (" .. seq_num .. ")")
        local ack_num = buffer(3, 2):uint()
        podstrom:add(k_ack_num, buffer(3, 2)):append_text(" (" .. ack_num .. ")")
    end
	if msg_type == 'k' then
		msg_type_item:append_text(" (" .. "3F sprava" .. ")")
        local seq_num = buffer(1, 2):uint()
        podstrom:add(k_seq_num, buffer(1, 2)):append_text(" (" .. seq_num .. ")")
        local ack_num = buffer(3, 2):uint()
        podstrom:add(k_ack_num, buffer(3, 2)):append_text(" (" .. ack_num .. ")")
    end
	if msg_type == 'e' then
		msg_type_item:append_text(" (" .. "KEEP-ALIVE sprava" .. ")")
        local kseq_num = buffer(1, 4):uint()
        podstrom:add(k_kseq_num, buffer(1, 4)):append_text(" (" .. kseq_num .. ")")
    end
	if msg_type == 'o' then
		msg_type_item:append_text(" (" .. "KEEP-ALIVE-ACK sprava" .. ")")
        local kack_num = buffer(1, 4):uint()
        podstrom:add(k_kack_num, buffer(1, 4)):append_text(" (" .. kack_num .. ")")
    end
	if msg_type == 't' or msg_type == 'p' then
		msg_type_item:append_text(" (" .. "Prva sprava, posielana pred samotnymi datami" .. ")")
        local max_seq_num = buffer(1, 4):uint()
        podstrom:add(k_max_seq_num, buffer(1, 4)):append_text(" (" .. max_seq_num .. ")")
		if msg_type == 'p' then
			local payload = buffer(5):string()
			if payload then
				podstrom:add(k_payload, buffer(5))
			end
		end
    end
	if msg_type == 'r' then
		msg_type_item:append_text(" (" .. "RET sprava" .. ")")
	    if buffer:len() == 3 then
            podstrom:add("Ziadne fragmenty z tejto skupiny fragmentov nie je potrebne znovu odoslat")
		end
	    if buffer:len() > 3 then
			local ret_len = buffer:len()
			local ret_data = buffer(2, ret_len - 3)
            podstrom:add(k_ret_data, ret_data)
		end
	end
	if msg_type == 'x' or msg_type == 'y' then
		msg_type_item:append_text(" (" .. "Data sprava" .. ")")
        local mseq_num = buffer(1, 4):uint()
        podstrom:add(k_mseq_num, buffer(1, 4)):append_text(" (" .. mseq_num .. ")")
        if buffer:len() >= 7 then
            local checksum = buffer(5, 2):uint()
            podstrom:add(k_checksum, buffer(5, 2))
        end
        local payload = buffer(7):string()
        if payload then
            podstrom:add(k_payload, buffer(7))
        end
    end
end

udp_table = DissectorTable.get("udp.port")
udp_table:add(65001, nikinprotokol)
udp_table:add(65002, nikinprotokol)