module("luci.controller.admin.security",package.seeall)

local http = require("luci.http")
local protocol = require("luci.http.protocol")
local json = require("luci.json")
local log = require("luci.log")

--log.print("-------------------------------------------------------")
--log.print("Log start!")

function index()
	entry({"admin","security"},template("admin_security/security"),("Security"),89).index = false
	entry({"admin","security","process"},call("Device_page"),"Add/List Devices",4).dependent=false
	entry({"admin","security","rule"}, firstchild(),"Rules",5).dependent=false
	entry({"admin","security","rule","rules_1"},call("Rule_General"),"General",6).dependent=false
	--entry({"admin","security","rule","rules_2"},call("Rule_Advanced"),"Advanced",7).dependent=false
	--entry({"admin","security","verdict_1"},call("Verdict_1"),"",9).dependent=false
	--entry({"admin","security","verdict_2"},call("Verdict_2"),"",10).depentdent=false
	entry({"admin","security","unauth_device"},call("unauth_device"),"",7).sysauth=false
	entry({"admin","security","unauth_rule"},call("unauth_rule"),"",8).sysauth=false
end

function unauth_rule()
	------------------------------------------------------------------------
	-----------------------------hardcoded----------------------------------
	local vlan = ""
	local file = io.open("/var/run/warden.vlan","r")
	for line in file:lines() do
		vlan = line
	end
	file:close()
	os.remove("/var/run/warden.vlan")
	------------------------------------------------------------------------
	------------------------------------------------------------------------
	local http_method = http.getenv("REQUEST_METHOD")
	if http_method == "POST" then
		local delete = http.formvalue("delete")
		local accept = http.formvalue("accept")
		local reject = http.formvalue("reject")
		if delete ~= nil and accept == nil and reject == nil then
			if (check_rule(delete,vlan)) then
				delete_rule()
			else
				http.redirect(luci.dispatcher.build_url("admin","security","unauth_rule"))
			end
		elseif accept ~= nil and delete == nil and reject == nil then
			if (check_rule(accept,vlan)) then
				accept_rule_general()
			else
				http.redirect(luci.dispatcher.build_url("admin","security","unauth_rule"))
			end
		elseif reject ~= nil and accept == nil and delete == nil then
			if (check_rule(reject,vlan)) then
				reject_rule_general()
			else
				http.redirect(luci.dispatcher.build_url("admin","security","unauth_rule"))
			end
		end
		http.redirect(luci.dispatcher.build_url("admin","security","unauth_rule"))
	end
	luci.template.render("admin_security/unauth_rule",{
		permanent = unauth_perm_rule_table(vlan),
		temp = unauth_temp_rule_table(vlan),
		links = GenerateLinks(),
		nodes = GenerateNodes()
	})
end   

-- Used to check whether rules' dst_vlan matches current vlan
function check_rule(rule,vlan)
	local x=luci.model.uci.cursor()
	if (x:get("dreamcatcher",rule,"dst_vlan")==vlan) then
		return true
	else
		return false
	end
end

function Verdict_1()                                                                                              
	local http_method = http.getenv("REQUEST_METHOD")                                                         
	if http_method ~= "GET" then                                                                              
		http.redirect(luci.dispatcher.build_url("admin","security","rule","rules_1"))                     
	else                                                                                                      
		local id = http.formvalue("id")                                                                   
		if id == nil then                                                                                 
			http.redirect(luci.dispatcher.build_url("admin","security","rule","rules_1"))             
		else                                                                                                
			local x = luci.model.uci.cursor()                                                           
			local message = x:get("dreamcatcher",id,"message")                                          
			local src_vlan = x:get("dreamcatcher",id,"src_vlan")                                        
			local dst_vlan = x:get("dreamcatcher",id,"dst_vlan")                                        
			local proto = x:get("dreamcatcher",id,"proto")                                              
			local src_ip = x:get("dreamcatcher",id,"src_ip")                                            
			local dst_ip = x:get("dreamcatcher",id,"dst_ip")                                            
			local src_port = x:get("dreamcatcher",id,"src_port")                                                                                   
			local dst_port = x:get("dreamcatcher",id,"dst_port")                                                                                   
			local approved = x:get("dreamcatcher",id,"approved")                                                                                   
			if (message == nil or approved ~= '0') then                                                                                            
				http.redirect(luci.dispatcher.build_url("admin","security","rule","rules_1"))                                                  
			else                                                                                                                                   
				local content = "<tr>"                                                           
				.. "<td style=\"text-align:center\">"                               
				.. '<form style="margin:0px;display:inline" id="' .. id .. "accept" .. '" action="rule/rules_1" method="POST">'
				.. '<input type="hidden" name="accept" value="' .. id .. '"></input>'                                          
				.. '<input type="submit" value="Accept"></input>'           
				.. '</form>'                                                                                                   
				.. "</td>"                                                                                                     
				.. "<td style=\"text-align:center\">"                                                                          
				.. '<form style="margin:0px;display:inline" id="' .. id .. "reject" .. '" action="rule/rules_1" method="POST">'
				.. '<input type="hidden" name="reject" value="' .. id .. '"></input>'                                          
				.. '<input type="submit" value="Reject"></input>'           
				.. '</form>'                                                                                                   
				.. "</td>"                                                                                                     
				.. "</tr>"                                                                                                     
				luci.template.render("admin_security/verdict_1",{                                                                              
					id = id,
					message = message,                                                                                                     
					content = content                                                                                                      
				})                                                                                                                             
			end                                                                                                                                    
		end                                                                                                                                            
	end                                                                                                                                                    
end                                       

function Verdict_2()
	local http_method = http.getenv("REQUEST_METHOD")
	if http_method ~= "GET" then
		http.redirect(luci.dispatcher.build_url("admin","security","rule","rules_2"))
	else
		local id = http.formvalue("id")
		if id == nil then
			http.redirect(luci.dispatcher.build_url("admin","security","rule","rules_2"))
		else
			local x = luci.model.uci.cursor()
			local message = x:get("dreamcatcher",id,"message")
			local src_vlan = x:get("dreamcatcher",id,"src_vlan")
			local dst_vlan = x:get("dreamcatcher",id,"dst_vlan")
			local proto = x:get("dreamcatcher",id,"proto")
			local src_ip = x:get("dreamcatcher",id,"src_ip")
			local dst_ip = x:get("dreamcatcher",id,"dst_ip")
			local src_port = x:get("dreamcatcher",id,"src_port")
			local dst_port = x:get("dreamcatcher",id,"dst_port")
			local approved = x:get("dreamcatcher",id,"approved")
			if (message == nil or approved ~= '0') then
				http.redirect(luci.dispatcher.build_url("admin","security","rule","rules_2"))                      
			else 
				local content = "<tr>" 
				.. "<td style=\"text-align:center\">proto</td>"
				.. "<td style=\"text-align:center\">" .. (proto or "") .. "</td>"
				.. "</tr>"
				.. "<tr>"
				.. "<td style=\"text-align:center\">src_ip</td>"
				.. "<td style=\"text-align:center\">" .. (src_ip or "") .. "</td>"
				.. "</tr>"
				.. "<tr>"                                                                                                                                                   
				.. "<td style=\"text-align:center\">dst_ip</td>"                                                                                                                                        
				.. "<td style=\"text-align:center\">" .. (dst_ip or "") .. "</td>"                                                                                                                              
				.. "</tr>"
				.. "<tr>"                                                                                                                                                   
				.. "<td style=\"text-align:center\">src_port</td>"                                                                                                                                        
				.. "<td style=\"text-align:center\">" .. (src_port or "") .. "</td>"                                                                                                                              
				.. "</tr>"
				.. "<tr>"                                                                                                                                                   
				.. "<td style=\"text-align:center\">dst_port</td>"                                                                                                                                        
				.. "<td style=\"text-align:center\">" .. (dst_port or "") .. "</td>"                                                                                                                              
				.. "</tr>"                                                                                                                               
				.. "<tr>"
				.. "<td style=\"text-align:center\">"                                                                                                                                                   
				.. '<form style="margin:0px;display:inline" id="' .. id .. "accept" .. '" action="rule/rules_2" method="POST">'                                                                     
				.. '<input type="hidden" name="accept" value="' .. id .. '"></input>'                                                                                                   
				.. '<input type="submit" value="Accept"></input>'                                                                    
				.. '</form>'
				.. "</td>"
				.. "<td style=\"text-align:center\">"                                                                                                                                                                
				.. '<form style="margin:0px;display:inline" id="' .. id .. "reject" .. '" action="rule/rules_2" method="POST">'                                                                     
				.. '<input type="hidden" name="reject" value="' .. id .. '"></input>'                                                                                                   
				.. '<input type="submit" value="Reject"></input>'                                                                    
				.. '</form>'
				.. "</td>"
				.. "</tr>"
				luci.template.render("admin_security/verdict_2",{
					id = id,
					message = message,
					content = content
				})
			end						
		end
	end
end

function Device_page()
	local http_method = http.getenv("REQUEST_METHOD")
	if http_method == "POST" then
		local dname = http.formvalue("device_name")
		local delete = http.formvalue("delete_device")
		if dname~=nil then
			message = add_devices()
			luci.template.render("admin_security/password",{                                                                                                                                          
				TODO = message,                                                                                                                                                                   
				table_text = GenerateTable()                                                                                                                                                      
			})
		elseif delete ~= nil then
			delete_devices()
		else
			http.redirect(luci.dispatcher.build_url("admin","security","process"))
		end
	elseif http_method == "GET" then
		luci.template.render("admin_security/password",{
			TODO = "",
			table_text = GenerateTable()
		})
	else
		luci.template.render("admin_security/password",{
			TODO = "",
			table_text = GenerateTable()
		})
	end
end

function unauth_device()
	local http_method = http.getenv("REQUEST_METHOD")
	if http_method == "POST" then
		local dname = http.formvalue("device_name")
		if dname~=nil then
			message = add_devices()
			luci.template.render("admin_security/unauth_device",{
				TODO = message
			})
		else 
			http.redirect(luci.dispatcher.build_url("admin","security","unauth_device"))
		end
	elseif http_method == "GET" then
		luci.template.render("admin_security/unauth_device",{
			TODO = ""
		})
	else
		luci.template.render("admin_security/unauth_device",{
			TODO = ""
		})
	end
end

function Rule_General()                                 
	local http_method = http.getenv("REQUEST_METHOD")
	if http_method == "POST" then                  
		--log.print("Got Post")
		local delete = http.formvalue("delete")
		local accept = http.formvalue("accept")
		local reject = http.formvalue("reject")
		--local accept_all_rule = http.formvalue("accept_all_rule")
		local src_vlan = http.formvalue("src_vlan")
		if delete~=nil then      
			delete_rule()    
		elseif accept ~= nil then
			accept_rule_general()    
		elseif reject ~= nil then
			reject_rule_general()
		elseif src_vlan ~= nil then              
			add_rule()
			--elseif accept_all_rule ~= nil then
			--	accept_all_rules()
		end                                  
		http.redirect(luci.dispatcher.build_url("admin","security","rule"));
		--http.redirect(luci.dispatcher.build_url("admin","security","rule","rules_1"));
	end                                          
	luci.template.render("admin_security/rules_1",{
		permanent = general_perm_rule_table(),
		temp = general_temp_rule_table(),
		links = GenerateLinks(),
		nodes = GenerateNodes()
	})
end   

function unauth_perm_rule_table(vlan)
	local x = luci.model.uci.cursor()
	local flag = false
	local permanent_table = '<table style="width:100%;margin:0px">' ..                           
	"<tr>" ..                                                                                      
	"<td>Message</td>" ..                                                                
	"<td width=\"55\">Verdict</td>" ..                                     
	"<td width=\"48\"></td>" ..                                            
	"</tr>"
	x:foreach("dreamcatcher","rule",function(s)
		local IcName = s[".name"]
		local approved = x:get("dreamcatcher",IcName,"approved")
		if approved == "1" then
			permanent_table = permanent_table .. "<tr>\n"
			local src_device = ""                                                                                                  
			local dst_device = ""                                                                                                  
			local device_name = ""                                                                                                 
			local src_vlan = x:get("dreamcatcher",IcName,"src_vlan")                                                               
			local dst_vlan = x:get("dreamcatcher",IcName,"dst_vlan")
			if src_vlan == vlan or dst_vlan == vlan then
				flag = true
				if src_vlan == nil then                                                                                                
					src_device = "Unknown device"                                                                                  
				else                                                                                                                   
					src_device = GetDeviceName(src_vlan)                                                                           
				end                                                                                                                    
				if dst_vlan == nil then                                                                                                
					dst_device = "Unknown device"                                                                           
				else                                                                                                                   
					dst_device = GetDeviceName(dst_vlan)                                                                           
				end

				local device_names = x:get("dreamcatcher",IcName,"device_name")
				if device_names == nil then
					device_names = "Unknown device"
				end
				local type = x:get("dreamcatcher",IcName,"type")
				if type == "3" then -- if this is an advertisement, we're going to display multiple rules
					for k,device_name in pairs(device_names) do
						local message = GetTitle(src_device,dst_device,device_name,type) 
						--local message = x:get("dreamcatcher",IcName,"message")                                                                                                                              
						permanent_table = permanent_table .. "<td>" .. message .. "</td>\n"
						local verdict = x:get("dreamcatcher",IcName,"verdict")                                           
						if verdict ~= nil then                                                                           
							permanent_table = permanent_table .. "<td>" .. verdict .. "</td>\n"                      
						else                                                                                             
							permanent_table = permanent_table .. "<td></td>\n"                
						end
						permanent_table = permanent_table                                           
						.. '<td><form style="margin:0px;display: inline" id="' .. IcName .. "delete" .. '" action="" method="POST">'
						.. '<input type="hidden" name="delete" value="' .. IcName .. '"></input>'                              
						.. '<input type="submit" value="Delete"></input>'
						.. '</form></td>'                                                                                      
						permanent_table = permanent_table .. "</tr>" 
					end
				else
					local message = GetTitle(src_device,dst_device,device_name,type) 
					--local message = x:get("dreamcatcher",IcName,"message")                                                                                                                              
					permanent_table = permanent_table .. "<td>" .. message .. "</td>\n"
					local verdict = x:get("dreamcatcher",IcName,"verdict")                                           
					if verdict ~= nil then                                                                           
						permanent_table = permanent_table .. "<td>" .. verdict .. "</td>\n"                      
					else                                                                                             
						permanent_table = permanent_table .. "<td></td>\n"                
					end
					permanent_table = permanent_table                                           
					.. '<td><form style="margin:0px;display: inline" id="' .. IcName .. "delete" .. '" action="" method="POST">'
					.. '<input type="hidden" name="delete" value="' .. IcName .. '"></input>'                              
					.. '<input type="submit" value="Delete"></input>'
					.. '</form></td>'                                                                                      
					permanent_table = permanent_table .. "</tr>" 
				end
				local device_name = x:get("dreamcatcher",IcName,"device_name")                                                         
				if device_name == nil then                                                                                             
					device_name = "Unknown device"                                                                              
				end                                                                                                                    
			end
		end
	end
	)
	--x:foreach("dreamcatcher","dpi_rule",function(s)                                                                                         
	--              local IcName = s[".name"]                                                                                                      
	--              local approved = x:get("dreamcatcher",IcName,"approved")                                                                        
	--              if approved == "1" then                                                                                                            
	--                      permanent_table = permanent_table .. "<tr>\n"                                                                          
	--                      local src_device = ""                                                                                                  
	--                      local dst_device = ""                                                                                                  
	--                      local device_name = ""                                                                                                 
	--                      local src_vlan = x:get("dreamcatcher",IcName,"src_vlan")                                                        
	--                      local dst_vlan = x:get("dreamcatcher",IcName,"dst_vlan")
	--		if src_vlan == vlan or dst_vlan == vlan then
	--			flag = true
	--			if src_vlan == nil then                                                                                                
	--                      	        src_device = "Unknown device"                                                                           
	--                      	else                                                                                                                   
	--                      	        src_device = GetDeviceName(src_vlan)                                                                           
	--                      	end                                                                                                                    
	--                      	if dst_vlan == nil then                                                                                                
	--                      	        dst_device = "Unknown device"                                                                                  
	--                      	else                                                                                                                   
	--                      	        dst_device = GetDeviceName(dst_vlan)                                                                           
	--                      	end                                                                                                                 
	--                      	local device_name = x:get("dreamcatcher",IcName,"device_name")                                                         
	--                      	if device_name == nil then                                                                                          
	--                             		device_name = "Unknown device"                                                                                 
	--                      	end                                                                                                                 
	--                      	local type = x:get("dreamcatcher",IcName,"type")                                                                       
	--                      	local message = GetTitle(src_device,dst_device,device_name,type)                                                
	--                      	--local message = x:get("dreamcatcher",IcName,"message")                                                               
	--                      	permanent_table = permanent_table .. "<td>" .. message .. "</td>\n"                                                    
	--                      	local verdict = x:get("dreamcatcher",IcName,"verdict")                                                                 
	--                      	if verdict ~= nil then                                                                                                 
	--                      	        permanent_table = permanent_table .. "<td>" .. verdict .. "</td>\n"                                            
	--                      	else                                                                                                                   
	--                      	        permanent_table = permanent_table .. "<td></td>\n"                                                             
	--                      	end                                                                                                                    
	--                      	permanent_table = permanent_table                                                                               
	--                              	.. '<td><form style="margin:0px;display: inline" id="' .. IcName .. "delete" .. '" action="" method="POST">'   
	--                              	.. '<input type="hidden" name="delete" value="' .. IcName .. '"></input>'                                   
	--                              if dst_vlan == vlan then
	--				permanent_table = permanent_table .. '<input type="button" onclick="modify_rule_2(\'' .. IcName .. '\',\'delete\')" value="Delete"></input>'       
	--                              end                                                                                           
	--                      	permanent_table = permanent_table .. "</form></td></tr>"                                                                        
	--              	end
	--	end                                                                                                                         
	--      end                                                                                                                                 
	--      )
	permanent_table = permanent_table .. "</table>"
	if flag == true then
		return permanent_table
	else
		return "<table style=\"width=100%;margin:0px\"><tr><td>Currently no rules</td></tr></table>"                                                                      
	end
end

function unauth_temp_rule_table(vlan)
	local x = luci.model.uci.cursor()                                                                                              
	local flag = false                                                                               
	local temp_table = '<table style="width:100%;margin:0px">' ..                                                                  
	"<tr>" ..                                                                                        
	"<td>Message</td>" ..                                                                                                  
	"<td width=\"150\"<td>" ..                                                                                             
	"</tr>"
	x:foreach("dreamcatcher","rule",function(s)
		local IcName = s[".name"]
		local approved = x:get("dreamcatcher",IcName,"approved")
		if approved == "0" then
			temp_table = temp_table .. "<tr>\n"
			local src_device = ""
			local dst_device = ""
			local device_name = ""
			local src_vlan = x:get("dreamcatcher",IcName,"src_vlan")
			local dst_vlan = x:get("dreamcatcher",IcName,"dst_vlan")
			if dst_vlan == vlan then
				flag = true
				if src_vlan == nil then
					src_device = "Unknown device"
				else
					src_device = GetDeviceName(src_vlan)
				end
				if dst_vlan == nil then
					dst_device = "Unknown device"
				else
					dst_device = GetDeviceName(dst_vlan)
				end
				local device_names = x:get("dreamcatcher",IcName,"device_name")
				if device_names == nil then
					device_names = "Unknown device"
				end
				local type = x:get("dreamcatcher",IcName,"type")
				if type == "3" then -- if this is an advertisement, we're going to display multiple rules
					for k,device_name in pairs(device_names) do
						local message = GetTitle(src_device,dst_device,device_name,type)
						--local message = x:get("dreamcatcher",IcName,"message")                                                                                                                              
						temp_table = temp_table .. "<td>" .. message .. "</td>\n" 			
						temp_table = temp_table .. "<td>"                                                                              
						.. '<form style="margin:0px;display:inline" id="' .. IcName .. "accept" .. '" action="" method="POST">'
						.. '<input type="hidden" name="accept" value="' .. IcName .. '"></input>'                              
						.. '<input type="submit" value="Accept"></input>'
						.. '</form>'                                                                                           
						.. '<form style="margin:0px;display:inline" id="' .. IcName .. "reject" .. '" action="" method="POST">'
						.. '<input type="hidden" name="reject" value="' .. IcName .. '"></input>'                              
						.. '<input type="submit" value="Reject"></input>'
						.. '</form>'                                                                                           
						.. '<form style="margin:0px;display:inline" id="' .. IcName .. "delete" .. '" action="" method="POST">'
						.. '<input type="hidden" name="delete" value="' .. IcName .. '"></input>'                              
						.. '<input type="submit" value="Delete"></input>'
						.. '</form></td>'                                                                                      
						temp_table = temp_table .. "</tr>"
					end
				else
					local message = GetTitle(src_device,dst_device,device_name,type)
					--local message = x:get("dreamcatcher",IcName,"message")                                                                                                                              
					temp_table = temp_table .. "<td>" .. message .. "</td>\n" 			
					temp_table = temp_table .. "<td>"                                                                              
					.. '<form style="margin:0px;display:inline" id="' .. IcName .. "accept" .. '" action="" method="POST">'
					.. '<input type="hidden" name="accept" value="' .. IcName .. '"></input>'                              
					.. '<input type="submit" value="Accept"></input>'
					.. '</form>'                                                                                           
					.. '<form style="margin:0px;display:inline" id="' .. IcName .. "reject" .. '" action="" method="POST">'
					.. '<input type="hidden" name="reject" value="' .. IcName .. '"></input>'                              
					.. '<input type="submit" value="Reject"></input>'
					.. '</form>'                                                                                           
					.. '<form style="margin:0px;display:inline" id="' .. IcName .. "delete" .. '" action="" method="POST">'
					.. '<input type="hidden" name="delete" value="' .. IcName .. '"></input>'                              
					.. '<input type="submit" value="Delete"></input>'
					.. '</form></td>'                                                                                      
					temp_table = temp_table .. "</tr>"
				end
			end
		end	
	end)
	--x:foreach("dreamcatcher","dpi_rule",function(s)                                                         
	--              local IcName = s[".name"]                                                                   
	--              local approved = x:get("dreamcatcher",IcName,"approved")                                        
	--              if approved == "0" then                                                                         
	--                      temp_table = temp_table .. "<tr>\n"                                                 
	--                      local src_device = ""                                                               
	--                      local dst_device = ""                                                               
	--                      local device_name = ""                                                              
	--                      local src_vlan = x:get("dreamcatcher",IcName,"src_vlan")                            
	--                      local dst_vlan = x:get("dreamcatcher",IcName,"dst_vlan")
	--		if dst_vlan == vlan then
	--			flag = true
	--			if src_vlan == nil then                                                             
	--                      	        src_device = "Unknown device"                                               
	--                      	else                                                                                
	--                      	        src_device = GetDeviceName(src_vlan)                                        
	--                      	end                                                                                 
	--                      	if dst_vlan == nil then                                                             
	--                      	        dst_device = "Unknown device"                                               
	--                      	else                                                                                
	--                      	        dst_device = GetDeviceName(dst_vlan)                                        
	--                      	end                                                                                 
	--                      	local device_name = x:get("dreamcatcher",IcName,"device_name")                      
	--                      	if device_name == nil then                                                          
	--                      	        device_name = "Unknown device"                                              
	--                      	end                                                                                 
	--                      	local type = x:get("dreamcatcher",IcName,"type")                                    
	--                      	local message = GetTitle(src_device,dst_device,device_name,type)                    
	--                      	--local message = x:get("dreamcatcher",IcName,"message")                            
	--                      	temp_table = temp_table .. "<td>" .. message .. "</td>\n"                           
	--                      	temp_table = temp_table .. "<td>"                                                                              
	--                      		.. '<form style="margin:0px;display:inline" id="' .. IcName .. "accept" .. '" action="" method="POST">'
	--                      		.. '<input type="hidden" name="accept" value="' .. IcName .. '"></input>'                              
	--                      		.. '<input type="button" onclick="modify_rule_2(\'' .. IcName .. '\',\'accept\')" value="Accept"></input>'
	--                      		.. '</form>'                                                                                           
	--                      		.. '<form style="margin:0px;display:inline" id="' .. IcName .. "reject" .. '" action="" method="POST">'
	--                      		.. '<input type="hidden" name="reject" value="' .. IcName .. '"></input>'                              
	--                      		.. '<input type="button" onclick="modify_rule_2(\'' .. IcName .. '\',\'reject\')" value="Reject"></input>'
	--                      		.. '</form>'                                                                                           
	--                      		.. '<form style="margin:0px;display:inline" id="' .. IcName .. "delete" .. '" action="" method="POST">'
	--                      		.. '<input type="hidden" name="delete" value="' .. IcName .. '"></input>'                              
	--                      		.. '<input type="button" onclick="modify_rule_2(\'' .. IcName .. '\',\'delete\')" value="Delete"></input>'
	--                      		.. '</form></td>'                                                                                      
	--                      	temp_table = temp_table .. "</tr>"                                                  
	--          		end
	--	end            	                                                                             
	--      end)
	temp_table = temp_table .. "</table>"
	if flag == true then
		return temp_table
	else
		return "<table style=\"width=100%;margin:0px\"><tr><td>Currently no rules</td></tr></table>"
	end
end

function Rule_Advanced()
	local http_method = http.getenv("REQUEST_METHOD")
	if http_method == "POST" then
		--log.print("Got Post")
		local delete = http.formvalue("delete")
		local accept = http.formvalue("accept")
		local reject = http.formvalue("reject")
		local accept_all_rule = http.formvalue("accept_all_rule")
		if delete~=nil then
			delete_rule()
		elseif accept ~= nil then
			accept_rule_advanced()
		elseif reject ~= nil then
			reject_rule_advanced()
		elseif accept_all_rule ~= nil then
			accept_all_rules()
		else
			add_rule()
		end
		http.redirect(luci.dispatcher.build_url("admin","security","rule","rules_2"));
	else
		luci.template.render("admin_security/rules_2",{                                     
			permanent = advanced_perm_rule_table(),                                              
			temp = advanced_temp_rule_table()       
		})
	end 
end

function accept_rule_advanced()
	local accept_rule = http.formvalue("accept")
	local x = luci.model.uci.cursor()
	if (x:get("dreamcatcher",accept_rule,"approved")=="0") then
		x:set("dreamcatcher",accept_rule,"approved","1")
		x:set("dreamcatcher",accept_rule,"verdict","ACCEPT")
		x:commit("dreamcatcher")
		os.execute("/sbin/fw3 reload-dreamcatcher")
	end
end

function reject_rule_advanced()
	local reject_rule = http.formvalue("reject")                                                                                   
	local x = luci.model.uci.cursor()                                                                                              
	if (x:get("dreamcatcher",reject_rule,"approved")=="0") then                                                                        
		x:set("dreamcatcher",reject_rule,"approved","1")                                                                       
		x:set("dreamcatcher",reject_rule,"verdict","REJECT")                                                                   
		x:commit("dreamcatcher")                                                                                               
		os.execute("/sbin/fw3 reload-dreamcatcher")
	end
end

function accept_rule_general()
	local accept_rule = http.formvalue("accept")
	local x = luci.model.uci.cursor()
	if (x:get("dreamcatcher",accept_rule,"approved")=="0") then
		local src_vlan = x:get("dreamcatcher",accept_rule,"src_vlan")	
		local dst_vlan = x:get("dreamcatcher",accept_rule,"dst_vlan")
		local type = x:get("dreamcatcher",accept_rule,"type")
		local dst_ip = x:get("dreamcatcher",accept_rule,"dst_ip")
		if (src_vlan == nil) then
			src_vlan = ""
		end
		if (dst_vlan == nil) then
			dst_vlan = ""
		end
		if (type == nil) then
			type = ""
		end
		if (dst_ip == nil) then
			dst_ip = ""
		end
		local string_1 = "type" .. type .. "src_vlan" .. src_vlan .. "dst_vlan" .. dst_vlan .. "proto"  .. "src_ip" 
		.. "dst_ip" .. "src_port" .. "dst_port"  		
		local string_2 = "type" .. type .. "src_vlan" .. src_vlan .. "dst_vlan" .. "proto"  .. "src_ip"                                                                                 
		.. "dst_ip" .. dst_ip .. "src_port" .. "dst_port"
		if type == "0" then
			local flag = false
			x:foreach("dreamcatcher","rule",function(s)                                                                                            
				local IcName = s[".name"]                                                                                                      
				local vlan1 = x:get("dreamcatcher",IcName,"src_vlan")
				local vlan2 = x:get("dreamcatcher",IcName,"dst_vlan")
				local type_temp = x:get("dreamcatcher",IcName,"type")
				if (vlan1 == src_vlan and vlan2 == dst_vlan and type_temp == type) then
					if (x:delete("dreamcatcher",IcName)) then
						flag = true
					end
				end
			end)
			if (flag == true) then
				local name = getMD5(string_1)                                                                                    
				x:set("dreamcatcher",name,"rule")                                                                              
				if (src_vlan ~= "") then                                                                                       
					x:set("dreamcatcher",name,"src_vlan",src_vlan)                                                         
				end                                                                                                            
				if (dst_vlan ~= "") then                                                                                       
					x:set("dreamcatcher",name,"dst_vlan",dst_vlan)                                                         
				end                                                                                                            
				if (type ~= "") then                                                                                          
					x:set("dreamcatcher",name,"type",type)                                                               
				end                                                                                                            
				x:set("dreamcatcher",name,"approved","1")                                                                      
				x:set("dreamcatcher",name,"verdict","ACCEPT")                                                                  
				x:commit("dreamcatcher")                                                                                    
				os.execute("/sbin/fw3 reload-dreamcatcher")
			elseif (x:delete("dreamcatcher",accept_rule)) then
				local name = getMD5(string_1)                                                                                            
				x:set("dreamcatcher",name,"rule")   			
				if (src_vlan ~= "") then
					x:set("dreamcatcher",name,"src_vlan",src_vlan)
				end
				if (dst_vlan ~= "") then
					x:set("dreamcatcher",name,"dst_vlan",dst_vlan)
				end
				if (type ~= "") then
					x:set("dreamcatcher",name,"type",type)
				end
				x:set("dreamcatcher",name,"approved","1")
				x:set("dreamcatcher",name,"verdict","ACCEPT")
				x:commit("dreamcatcher")
				os.execute("/sbin/fw3 reload-dreamcatcher")
			end
		elseif type == "1" then
			local flag = false
			x:foreach("dreamcatcher","rule",function(s)
				local IcName = s[".name"]
				local vlan = x:get("dreamcatcher",IcName,"src_vlan")
				local dst_ip_temp = x:get("dreamcatcher",IcName,"dst_ip")
				local type_temp = x:get("dreamcatcher",IcName,"type")
				if (vlan == src_vlan and dst_ip_temp == dst_ip and type_temp == type) then
					if (x:delete("dreamcatcher",IcName)) then
						flag = true
					end
				end
			end)
			if (flag == true) then
				local name = getMD5(string_2)
				x:set("dreamcatcher",name,"rule")
				if (src_vlan ~= "") then
					x:set("dreamcatcher",name,"src_vlan",src_vlan)
				end
				if (dst_ip ~= "") then
					x:set("dreamcatcher",name,"dst_ip",dst_ip)
				end
				if (type ~= "") then
					x:set("dreamcatcher",name,"type",type)
				end
				x:set("dreamcatcher",name,"approved","1")
				x:set("dreamcatcher",name,"verdict","ACCEPT")
				x:commit("dreamcatcher")                                                                                                                                                    
				os.execute("/sbin/fw3 reload-dreamcatcher")
			elseif (x:delete("dreamcatcher",accept_rule)) then                                                                                                                                  
				local name = getMD5(string_2)                                                                                                                                               
				x:set("dreamcatcher",name,"rule")                                                                                                                                           
				if (src_vlan ~= "") then                                                                                                                                                    
					x:set("dreamcatcher",name,"src_vlan",src_vlan)                                                                                                                      
				end                                                                                                                                                                         
				if (dst_ip ~= "") then                                                                                                                                                    
					x:set("dreamcatcher",name,"dst_ip",dst_ip)                                                                                                                      
				end                                                                                                                                                                         
				if (type ~= "") then                                                                                                                                                        
					x:set("dreamcatcher",name,"type",type)                                                                                                                              
				end                                                                                                                                                                         
				x:set("dreamcatcher",name,"approved","1")                                                                                                                                   
				x:set("dreamcatcher",name,"verdict","ACCEPT")                                                                                                                               
				x:commit("dreamcatcher")                                                                                                                                                    
				os.execute("/sbin/fw3 reload-dreamcatcher")                                                                                                                                 
			end
		elseif type == "2" then
			if (x:get("dreamcatcher",accept_rule,"approved")=="0") then                                                                                                                                         
				x:set("dreamcatcher",accept_rule,"approved","1")                                                                                                                                            
				x:set("dreamcatcher",accept_rule,"verdict","ACCEPT")                                                                                                                                        
				x:commit("dreamcatcher")                                                                                                                                                                    
				os.execute("/sbin/fw3 reload-dreamcatcher")                                                                                                                                                 
			end				
		elseif type == "3" then
			-- look for an existing ACCEPT rule, and if it exists, combine this rule with that one
			-- if no existing ACCEPT rule, approve and accept this one

			-- iterate over each rule and see if it matches this rule's type, src_vlan, proto, and that it has an ACCEPT target
			local found = false
			x:foreach("dreamcatcher","rule",function(s)
				if found == false then
					local IcName = s[".name"]
					local src_vlan_temp = x:get("dreamcatcher",IcName,"src_vlan")
					local type_temp = x:get("dreamcatcher",IcName,"type")
					local verdict_temp = x:get("dreamcatcher",IcName,"verdict")
					if (IcName ~= accept_rule and src_vlan == src_vlan_temp and type == type_temp and verdict_temp == "ACCEPT") then
						found = true
						-- combine this rule with that one
						local device_names = x:get("dreamcatcher",IcName,"device_name") -- that one
						local new_device_names = x:get("dreamcatcher",accept_rule,"device_name") -- this one
						for _,v in ipairs(new_device_names) do
							table.insert(device_names, v) -- put all names in device_names
						end
						x:set("dreamcatcher",IcName,"device_name", device_names) -- store combined list in that one
					end
				end
			end)
			if found == true then
				x:delete("dreamcatcher",accept_rule) -- remove this one
			else -- no existing ACCEPT rule, so approve and accept this one
				x:set("dreamcatcher",accept_rule,"approved","1")                                                                                                                                            
				x:set("dreamcatcher",accept_rule,"verdict","ACCEPT")                                                                                                                                        
			end
			x:commit("dreamcatcher")                                                                                                                                                                    
			os.execute("/sbin/fw3 reload-dreamcatcher")                                                                                                                                                 
		end
	end
end

function reject_rule_general()
	local reject_rule = http.formvalue("reject")
	local x = luci.model.uci.cursor()
	if (x:get("dreamcatcher",reject_rule,"approved")=="0") then
		local src_vlan = x:get("dreamcatcher",reject_rule,"src_vlan")	
		local dst_vlan = x:get("dreamcatcher",reject_rule,"dst_vlan")
		local type = x:get("dreamcatcher",reject_rule,"type")
		local dst_ip = x:get("dreamcatcher",reject_rule,"dst_ip")
		if (src_vlan == nil) then
			src_vlan = ""
		end
		if (dst_vlan == nil) then
			dst_vlan = ""
		end
		if (type == nil) then
			type = ""
		end
		if (dst_ip == nil) then
			dst_ip = ""
		end
		local string_1 = "type" .. type .. "src_vlan" .. src_vlan .. "dst_vlan" .. dst_vlan .. "proto"  .. "src_ip" 
		.. "dst_ip" .. "src_port" .. "dst_port"  		
		local string_2 = "type" .. type .. "src_vlan" .. src_vlan .. "dst_vlan" .. "proto"  .. "src_ip"                                                                                 
		.. "dst_ip" .. dst_ip .. "src_port" .. "dst_port"
		if type == "0" then
			local flag = false
			x:foreach("dreamcatcher","rule",function(s)                                                                                            
				local IcName = s[".name"]                                                                                                      
				local vlan1 = x:get("dreamcatcher",IcName,"src_vlan")
				local vlan2 = x:get("dreamcatcher",IcName,"dst_vlan")
				local type_temp = x:get("dreamcatcher",IcName,"type")
				if (vlan1 == src_vlan and vlan2 == dst_vlan and type_temp == type) then
					if (x:delete("dreamcatcher",IcName)) then
						flag = true
					end
				end
			end)
			if (flag == true) then
				local name = getMD5(string_1)                                                                                    
				x:set("dreamcatcher",name,"rule")                                                                              
				if (src_vlan ~= "") then                                                                                       
					x:set("dreamcatcher",name,"src_vlan",src_vlan)                                                         
				end                                                                                                            
				if (dst_vlan ~= "") then                                                                                       
					x:set("dreamcatcher",name,"dst_vlan",dst_vlan)                                                         
				end                                                                                                            
				if (type ~= "") then                                                                                          
					x:set("dreamcatcher",name,"type",type)                                                               
				end                                                                                                            
				x:set("dreamcatcher",name,"approved","1")                                                                      
				x:set("dreamcatcher",name,"verdict","REJECT")                                                                  
				x:commit("dreamcatcher")                                                                                    
				os.execute("/sbin/fw3 reload-dreamcatcher")
			elseif (x:delete("dreamcatcher",reject_rule)) then
				local name = getMD5(string_1)                                                                                            
				x:set("dreamcatcher",name,"rule")   			
				if (src_vlan ~= "") then
					x:set("dreamcatcher",name,"src_vlan",src_vlan)
				end
				if (dst_vlan ~= "") then
					x:set("dreamcatcher",name,"dst_vlan",dst_vlan)
				end
				if (type ~= "") then
					x:set("dreamcatcher",name,"type",type)
				end
				x:set("dreamcatcher",name,"approved","1")
				x:set("dreamcatcher",name,"verdict","REJECT")
				x:commit("dreamcatcher")
				os.execute("/sbin/fw3 reload-dreamcatcher")
			end
		elseif type == "1" then
			local flag = false
			x:foreach("dreamcatcher","rule",function(s)
				local IcName = s[".name"]
				local vlan = x:get("dreamcatcher",IcName,"src_vlan")
				local dst_ip_temp = x:get("dreamcatcher",IcName,"dst_ip")
				local type_temp = x:get("dreamcatcher",IcName,"type")
				if (vlan == src_vlan and dst_ip_temp == dst_ip and type_temp == type) then
					if (x:delete("dreamcatcher",IcName)) then
						flag = true
					end
				end
			end)
			if (flag == true) then
				local name = getMD5(string_2)
				x:set("dreamcatcher",name,"rule")
				if (src_vlan ~= "") then
					x:set("dreamcatcher",name,"src_vlan",src_vlan)
				end
				if (dst_ip ~= "") then
					x:set("dreamcatcher",name,"dst_ip",dst_ip)
				end
				if (type ~= "") then
					x:set("dreamcatcher",name,"type",type)
				end
				x:set("dreamcatcher",name,"approved","1")
				x:set("dreamcatcher",name,"verdict","REJECT")
				x:commit("dreamcatcher")                                                                                                                                                    
				os.execute("/sbin/fw3 reload-dreamcatcher")
			elseif (x:delete("dreamcatcher",reject_rule)) then                                                                                                                                  
				local name = getMD5(string_2)                                                                                                                                               
				x:set("dreamcatcher",name,"rule")                                                                                                                                           
				if (src_vlan ~= "") then                                                                                                                                                    
					x:set("dreamcatcher",name,"src_vlan",src_vlan)                                                                                                                      
				end                                                                                                                                                                         
				if (dst_ip ~= "") then                                                                                                                                                    
					x:set("dreamcatcher",name,"dst_ip",dst_ip)                                                                                                                      
				end                                                                                                                                                                         
				if (type ~= "") then                                                                                                                                                        
					x:set("dreamcatcher",name,"type",type)                                                                                                                              
				end                                                                                                                                                                         
				x:set("dreamcatcher",name,"approved","1")                                                                                                                                   
				x:set("dreamcatcher",name,"verdict","REJECT")                                                                                                                               
				x:commit("dreamcatcher")                                                                                                                                                    
				os.execute("/sbin/fw3 reload-dreamcatcher")                                                                                                                                 
			end
		elseif (type == "2" or type == "3") then
			if (x:get("dreamcatcher",reject_rule,"approved")=="0") then                                                                                                                                         
				x:set("dreamcatcher",reject_rule,"approved","1")                                                                                                                                            
				x:set("dreamcatcher",reject_rule,"verdict","REJECT")                                                                                                                                        
				x:commit("dreamcatcher")                                                                                                                                                                    
				os.execute("/sbin/fw3 reload-dreamcatcher")                                                                                                                                                 
			end				
		end
	end
end               

function advanced_perm_rule_table()
	local x = luci.model.uci.cursor()
	local flag = false
	local permanent_table = '<table style="width:100%;margin:0px">' ..
	"<tr>" ..
	"<td>Message</td>" ..
	"<td>Protocol</td>" ..
	"<td>Source IP</td>" ..
	"<td>Destination IP</td>" ..
	"<td>Source port</td>" ..
	"<td>Destination port</td>" ..
	"<td width=\"55\">Verdict</td>" ..                                                                                      
	"<td width=\"48\"></td>" .. 	
	"</tr>"
	x:foreach("dreamcatcher","rule",function(s)
		local IcName = s[".name"]
		local approved = x:get("dreamcatcher",IcName,"approved")
		if approved == "1" then
			flag = true
			permanent_table = permanent_table .. "<tr>"
			local src_device = ""                                                                                                  
			local dst_device = ""                                                                                                  
			local device_name = ""                                                                                              
			local src_vlan = x:get("dreamcatcher",IcName,"src_vlan")                                                               
			if src_vlan == nil then                                                                                             
				src_device = "Unknown device"                                                                                  
			else                                                                                                                
				src_device = GetDeviceName(src_vlan)                                                                           
			end                                                                                                             
			local dst_vlan = x:get("dreamcatcher",IcName,"dst_vlan")                                                               
			if dst_vlan == nil then                                                                                                
				dst_device = "Unknown device"                                                                                  
			else                                                                                                                   
				dst_device = GetDeviceName(dst_vlan)                                                                           
			end                                                                                                                    
			local device_name = x:get("dreamcatcher",IcName,"device_name")                                                         
			if device_name == nil then                                                                                             
				device_name = "Unknown device"                                                                              
			end                                                                                                                    
			local type = x:get("dreamcatcher",IcName,"type")                                                                    
			local message = GetTitle(src_device,dst_device,device_name,type)
			--local message = x:get("dreamcatcher",IcName,"message")
			permanent_table = permanent_table .. "<td>" .. message .. "</td>\n"
			local proto = x:get("dreamcatcher",IcName,"proto")
			if proto ~= nil then
				permanent_table = permanent_table .. "<td>" .. proto .. "</td>\n"
			else
				permanent_table = permanent_table .. "<td></td>\n"          
			end
			local src_ip = x:get("dreamcatcher",IcName,"src_ip")
			if src_ip ~= nil then
				permanent_table = permanent_table .. "<td>" .. src_ip .. "</td>\n"                                            
			else
				permanent_table = permanent_table .. "<td></td>\n"          
			end
			local dst_ip = x:get("dreamcatcher",IcName,"dst_ip")                                                          
			if dst_ip ~= nil then
				permanent_table = permanent_table .. "<td>" .. dst_ip .. "</td>\n"                                               
			else
				permanent_table = permanent_table .. "<td></td>\n"          
			end
			local src_port = x:get("dreamcatcher",IcName,"src_port")                                                          
			if src_port ~= nil then
				permanent_table = permanent_table .. "<td>" .. src_port .. "</td>\n"                                               
			else
				permanent_table = permanent_table .. "<td></td>\n"          
			end
			local dst_port = x:get("dreamcatcher",IcName,"dst_port")                                                          
			if dst_port ~= nil then
				permanent_table = permanent_table .. "<td>" .. dst_port .. "</td>\n"                                               
			else
				permanent_table = permanent_table .. "<td></td>\n"          
			end
			local verdict = x:get("dreamcatcher",IcName,"verdict")                                                          
			if verdict ~= nil then
				permanent_table = permanent_table .. "<td>" .. verdict .. "</td>\n"   
			else
				permanent_table = permanent_table .. "<td></td>\n"          
			end
			permanent_table = permanent_table 
			.. '<td><form style="margin:0px;display: inline" id="' .. IcName .. "delete" .. '" action="" method="POST">'
			.. '<input type="hidden" name="delete" value="' .. IcName .. '"></input>'   
			.. '<input type="submit" value="Delete"></input>'
			.. '</form></td>'
			permanent_table = permanent_table .. "</tr>"
		end
	end
	)
	x:foreach("dreamcatcher","dpi_rule",function(s)
		local IcName = s[".name"]
		local approved = x:get("dreamcatcher",IcName,"approved")
		if approved == "1" then
			flag = true
			permanent_table = permanent_table .. "<tr>"
			local src_device = ""                                                                                                  
			local dst_device = ""                                                                                                  
			local device_name = ""                                                                                              
			local src_vlan = x:get("dreamcatcher",IcName,"src_vlan")                                                               
			if src_vlan == nil then                                                                                             
				src_device = "Unknown device"                                                                                  
			else                                                                                                                
				src_device = GetDeviceName(src_vlan)                                                                           
			end                                                                                                             
			local dst_vlan = x:get("dreamcatcher",IcName,"dst_vlan")                                                               
			if dst_vlan == nil then                                                                                                
				dst_device = "Unknown device"                                                                                  
			else                                                                                                                   
				dst_device = GetDeviceName(dst_vlan)                                                                           
			end                                                                                                                    
			local device_name = x:get("dreamcatcher",IcName,"device_name")                                                         
			if device_name == nil then                                                                                             
				device_name = "Unknown device"                                                                              
			end                                                                                                                    
			local type = x:get("dreamcatcher",IcName,"type")                                                                    
			local message = GetTitle(src_device,dst_device,device_name,type)
			--local message = x:get("dreamcatcher",IcName,"message")
			permanent_table = permanent_table .. "<td>" .. message .. "</td>\n"
			local proto = x:get("dreamcatcher",IcName,"proto")
			if proto ~= nil then
				permanent_table = permanent_table .. "<td>" .. proto .. "</td>\n"
			else
				permanent_table = permanent_table .. "<td></td>\n"          
			end
			local src_ip = x:get("dreamcatcher",IcName,"src_ip")
			if src_ip ~= nil then
				permanent_table = permanent_table .. "<td>" .. src_ip .. "</td>\n"                                            
			else
				permanent_table = permanent_table .. "<td></td>\n"          
			end
			local dst_ip = x:get("dreamcatcher",IcName,"dst_ip")                                                          
			if dst_ip ~= nil then
				permanent_table = permanent_table .. "<td>" .. dst_ip .. "</td>\n"                                               
			else
				permanent_table = permanent_table .. "<td></td>\n"          
			end
			local src_port = x:get("dreamcatcher",IcName,"src_port")                                                          
			if src_port ~= nil then
				permanent_table = permanent_table .. "<td>" .. src_port .. "</td>\n"                                               
			else
				permanent_table = permanent_table .. "<td></td>\n"          
			end
			local dst_port = x:get("dreamcatcher",IcName,"dst_port")                                                          
			if dst_port ~= nil then
				permanent_table = permanent_table .. "<td>" .. dst_port .. "</td>\n"                                               
			else
				permanent_table = permanent_table .. "<td></td>\n"          
			end
			local verdict = x:get("dreamcatcher",IcName,"verdict")                                                          
			if verdict ~= nil then
				permanent_table = permanent_table .. "<td>" .. verdict .. "</td>\n"   
			else
				permanent_table = permanent_table .. "<td></td>\n"          
			end
			permanent_table = permanent_table 
			.. '<td><form style="margin:0px;display: inline" id="' .. IcName .. "delete" .. '" action="" method="POST">'
			.. '<input type="hidden" name="delete" value="' .. IcName .. '"></input>'   
			.. '<input type="submit" value="Delete"></input>'
			.. '</form></td>'
			permanent_table = permanent_table .. "</tr>"
		end
	end
	)
	permanent_table = permanent_table .. "</table>"
	if flag == true then
		return permanent_table
	else	
		return "<table style=\"width=100%;margin:0px\"><tr><td>Currently no rules</td></tr></table>"                                                                      
	end
end

function advanced_temp_rule_table()
	local x = luci.model.uci.cursor()
	local flag = false
	local temp_table = '<table style="width:100%;margin:0px">' ..                           
	"<tr>" ..                                                                         
	"<td>Message</td>" ..
	"<td>Protocol</td>" ..                                                    
	"<td>Source IP</td>" ..                                                   
	"<td>Destination IP</td>" ..                                              
	"<td>Source port</td>" ..                                                 
	"<td>Destination port</td>" ..                                            
	"<td width=\"150\"<td>" ..
	"</tr>"      
	x:foreach("dreamcatcher","rule",function(s)                                               
		local IcName = s[".name"]
		local approved = x:get("dreamcatcher",IcName,"approved")
		if approved == "0" then
			flag = true
			temp_table = temp_table .. "<tr>\n"                                         
			local src_device = ""                                                                                                  
			local dst_device = ""                                                                                                  
			local device_name = ""                                                                                              
			local src_vlan = x:get("dreamcatcher",IcName,"src_vlan")                                                               
			if src_vlan == nil then                                                                                             
				src_device = "Unknown device"                                                                                  
			else                                                                                                                
				src_device = GetDeviceName(src_vlan)                                                                           
			end                                                                                                             
			local dst_vlan = x:get("dreamcatcher",IcName,"dst_vlan")                                                               
			if dst_vlan == nil then                                                                                                
				dst_device = "Unknown device"                                                                                  
			else                                                                                                                   
				dst_device = GetDeviceName(dst_vlan)                                                                           
			end                                                                                                                    
			local device_name = x:get("dreamcatcher",IcName,"device_name")                                                         
			if device_name == nil then                                                                                             
				device_name = "Unknown device"                                                                              
			end                                                                                                                    
			local type = x:get("dreamcatcher",IcName,"type")                                                                    
			local message = GetTitle(src_device,dst_device,device_name,type)
			--local message = x:get("dreamcatcher",IcName,"message")
			temp_table = temp_table .. "<td>" .. message .. "</td>\n"
			local proto = x:get("dreamcatcher",IcName,"proto")
			if proto ~= nil then                                                      
				temp_table = temp_table .. "<td>" .. proto .. "</td>\n"
			else                                                                      
				temp_table = temp_table .. "<td></td>\n"                  
			end                                                                       
			local src_ip = x:get("dreamcatcher",IcName,"src_ip")                      
			if src_ip ~= nil then                                                     
				temp_table = temp_table .. "<td>" .. src_ip .. "</td>\n"  
			else                                                                      
				temp_table = temp_table .. "<td></td>\n"                  
			end                                                                     
			local dst_ip = x:get("dreamcatcher",IcName,"dst_ip")                      
			if dst_ip ~= nil then                                                     
				temp_table = temp_table .. "<td>" .. dst_ip .. "</td>\n"  
			else                                                                      
				temp_table = temp_table .. "<td></td>\n"                  
			end                                                                     
			local src_port = x:get("dreamcatcher",IcName,"src_port")               
			if src_port ~= nil then                                                   
				temp_table = temp_table .. "<td>" .. src_port .. "</td>\n"
			else                                                                      
				temp_table = temp_table .. "<td></td>\n"                  
			end                                                                       
			local dst_port = x:get("dreamcatcher",IcName,"dst_port")                
			if dst_port ~= nil then                                                   
				temp_table = temp_table .. "<td>" .. dst_port .. "</td>\n"
			else                                                                      
				temp_table = temp_table .. "<td></td>\n"                  
			end                                                                       
			temp_table = temp_table .. "<td>" 
			.. '<form style="margin:0px;display:inline" id="' .. IcName .. "accept" .. '" action="" method="POST">'                    
			.. '<input type="hidden" name="accept" value="' .. IcName .. '"></input>'                              
			.. '<input type="submit" value="Accept"></input>'          
			.. '</form>'
			.. '<form style="margin:0px;display:inline" id="' .. IcName .. "reject" .. '" action="" method="POST">'                    
			.. '<input type="hidden" name="reject" value="' .. IcName .. '"></input>'                              
			.. '<input type="submit" value="Reject"></input>'          
			.. '</form>'
			.. '<form style="margin:0px;display:inline" id="' .. IcName .. "delete" .. '" action="" method="POST">'
			.. '<input type="hidden" name="delete" value="' .. IcName .. '"></input>' 
			.. '<input type="submit" value="Delete"></input>' 
			.. '</form></td>'
			temp_table = temp_table .. "</tr>" 
		end                                                                          
	end                                                                               
	)
	x:foreach("dreamcatcher","dpi_rule",function(s)                                               
		local IcName = s[".name"]
		local approved = x:get("dreamcatcher",IcName,"approved")
		if approved == "0" then
			flag = true
			temp_table = temp_table .. "<tr>\n"                                         
			local src_device = ""                                                                                                  
			local dst_device = ""                                                                                                  
			local device_name = ""                                                                                              
			local src_vlan = x:get("dreamcatcher",IcName,"src_vlan")                                                               
			if src_vlan == nil then                                                                                             
				src_device = "Unknown device"                                                                                  
			else                                                                                                                
				src_device = GetDeviceName(src_vlan)                                                                           
			end                                                                                                             
			local dst_vlan = x:get("dreamcatcher",IcName,"dst_vlan")                                                               
			if dst_vlan == nil then                                                                                                
				dst_device = "Unknown device"                                                                                  
			else                                                                                                                   
				dst_device = GetDeviceName(dst_vlan)                                                                           
			end                                                                                                                    
			local device_name = x:get("dreamcatcher",IcName,"device_name")                                                         
			if device_name == nil then                                                                                             
				device_name = "Unknown device"                                                                              
			end                                                                                                                    
			local type = x:get("dreamcatcher",IcName,"type")                                                                    
			local message = GetTitle(src_device,dst_device,device_name,type)
			--local message = x:get("dreamcatcher",IcName,"message")
			temp_table = temp_table .. "<td>" .. message .. "</td>\n"
			local proto = x:get("dreamcatcher",IcName,"proto")
			if proto ~= nil then                                                      
				temp_table = temp_table .. "<td>" .. proto .. "</td>\n"
			else                                                                      
				temp_table = temp_table .. "<td></td>\n"                  
			end                                                                       
			local src_ip = x:get("dreamcatcher",IcName,"src_ip")                      
			if src_ip ~= nil then                                                     
				temp_table = temp_table .. "<td>" .. src_ip .. "</td>\n"  
			else                                                                      
				temp_table = temp_table .. "<td></td>\n"                  
			end                                                                     
			local dst_ip = x:get("dreamcatcher",IcName,"dst_ip")                      
			if dst_ip ~= nil then                                                     
				temp_table = temp_table .. "<td>" .. dst_ip .. "</td>\n"  
			else                                                                      
				temp_table = temp_table .. "<td></td>\n"                  
			end                                                                     
			local src_port = x:get("dreamcatcher",IcName,"src_port")               
			if src_port ~= nil then                                                   
				temp_table = temp_table .. "<td>" .. src_port .. "</td>\n"
			else                                                                      
				temp_table = temp_table .. "<td></td>\n"                  
			end                                                                       
			local dst_port = x:get("dreamcatcher",IcName,"dst_port")                
			if dst_port ~= nil then                                                   
				temp_table = temp_table .. "<td>" .. dst_port .. "</td>\n"
			else                                                                      
				temp_table = temp_table .. "<td></td>\n"                  
			end                                                                       
			temp_table = temp_table .. "<td>" 
			.. '<form style="margin:0px;display:inline" id="' .. IcName .. "accept" .. '" action="" method="POST">'                    
			.. '<input type="hidden" name="accept" value="' .. IcName .. '"></input>'                              
			.. '<input type="submit" value="Accept"></input>'          
			.. '</form>'
			.. '<form style="margin:0px;display:inline" id="' .. IcName .. "reject" .. '" action="" method="POST">'                    
			.. '<input type="hidden" name="reject" value="' .. IcName .. '"></input>'                              
			.. '<input type="submit" value="Reject"></input>'          
			.. '</form>'
			.. '<form style="margin:0px;display:inline" id="' .. IcName .. "delete" .. '" action="" method="POST">'
			.. '<input type="hidden" name="delete" value="' .. IcName .. '"></input>' 
			.. '<input type="submit" value="Delete"></input>' 
			.. '</form></td>'
			temp_table = temp_table .. "</tr>" 
		end                                                                          
	end                                                                               
	)
	temp_table = temp_table .. "</table>" 
	if flag == true then
		return temp_table
	else 
		return "<table style=\"width=100%;margin:0px\"><tr><td>Currently no rules</td></tr></table>"                                                                      
	end
end 	

function general_perm_rule_table()
	local x = luci.model.uci.cursor()
	local flag = false
	local permanent_table = '<table style="width:100%;margin:0px">' ..                           
	"<tr>" ..                                                                                      
	"<td>Message</td>" ..                                                                
	"<td width=\"55\">Verdict</td>" ..                                     
	"<td width=\"48\"></td>" ..                                            
	"</tr>"
	x:foreach("dreamcatcher","rule",function(s)
		local IcName = s[".name"]
		local approved = x:get("dreamcatcher",IcName,"approved")
		if approved == "1" then
			flag = true
			permanent_table = permanent_table .. "<tr>\n"
			local src_device = ""                                                                                                  
			local dst_device = ""                                                                                                  
			local device_name = ""                                                                                                 
			local src_vlan = x:get("dreamcatcher",IcName,"src_vlan")                                                               
			if src_vlan == nil then                                                                                                
				src_device = "Unknown device"                                                                                  
			else                                                                                                                   
				src_device = GetDeviceName(src_vlan)                                                                           
			end                                                                                                                    
			local dst_vlan = x:get("dreamcatcher",IcName,"dst_vlan")                                                            
			if dst_vlan == nil then                                                                                                
				dst_device = "Unknown device"                                                                           
			else                                                                                                                   
				dst_device = GetDeviceName(dst_vlan)                                                                           
			end                                                                                                                    
			local device_names = x:get("dreamcatcher",IcName,"device_name")
			if device_names == nil then
				device_names = "Unknown device"
			end
			local type = x:get("dreamcatcher",IcName,"type")
			if type == "3" then -- if this is an advertisement, we're going to display multiple rules
				for k,device_name in pairs(device_names) do
					local message = GetTitle(src_device,dst_device,device_name,type) 
					--local message = x:get("dreamcatcher",IcName,"message")                                                                                                                              
					permanent_table = permanent_table .. "<td>" .. message .. "</td>\n"
					local verdict = x:get("dreamcatcher",IcName,"verdict")                                           
					if verdict ~= nil then                                                                           
						permanent_table = permanent_table .. "<td>" .. verdict .. "</td>\n"                      
					else                                                                                             
						permanent_table = permanent_table .. "<td></td>\n"                
					end
					permanent_table = permanent_table                                           
					.. '<td><form style="margin:0px;display: inline" id="' .. IcName .. "delete" .. '" action="" method="POST">'
					.. '<input type="hidden" name="delete" value="' .. IcName .. "-" .. k .. '"></input>'                              
					.. '<input type="submit" value="Delete"></input>'
					.. '</form></td>'                                                                                      
					permanent_table = permanent_table .. "</tr>" 
				end
			else
				local message = GetTitle(src_device,dst_device,device_name,type) 
				--local message = x:get("dreamcatcher",IcName,"message")                                                                                                                              
				permanent_table = permanent_table .. "<td>" .. message .. "</td>\n"
				local verdict = x:get("dreamcatcher",IcName,"verdict")                                           
				if verdict ~= nil then                                                                           
					permanent_table = permanent_table .. "<td>" .. verdict .. "</td>\n"                      
				else                                                                                             
					permanent_table = permanent_table .. "<td></td>\n"                
				end
				permanent_table = permanent_table                                           
				.. '<td><form style="margin:0px;display: inline" id="' .. IcName .. "delete" .. '" action="" method="POST">'
				.. '<input type="hidden" name="delete" value="' .. IcName .. '"></input>'                              
				.. '<input type="submit" value="Delete"></input>'
				.. '</form></td>'                                                                                      
				permanent_table = permanent_table .. "</tr>" 
			end
			local device_name = x:get("dreamcatcher",IcName,"device_name")                                                         
			if device_name == nil then                                                                                             
				device_name = "Unknown device"                                                                              
			end                                                                                                                    
		end
	end
	)
	--x:foreach("dreamcatcher","dpi_rule",function(s)                                                                                         
	--              local IcName = s[".name"]                                                                                                      
	--              local approved = x:get("dreamcatcher",IcName,"approved")                                                                        
	--              if approved == "1" then                                                                                                            
	--                      flag = true                                                                                                            
	--                      permanent_table = permanent_table .. "<tr>\n"                                                                          
	--                      local src_device = ""                                                                                                  
	--                      local dst_device = ""                                                                                                  
	--                      local device_name = ""                                                                                                 
	--                      local src_vlan = x:get("dreamcatcher",IcName,"src_vlan")                                                        
	--                      if src_vlan == nil then                                                                                                
	--                              src_device = "Unknown device"                                                                           
	--                      else                                                                                                                   
	--                              src_device = GetDeviceName(src_vlan)                                                                           
	--                      end                                                                                                                    
	--                      local dst_vlan = x:get("dreamcatcher",IcName,"dst_vlan")                                                               
	--                      if dst_vlan == nil then                                                                                                
	--                              dst_device = "Unknown device"                                                                                  
	--                      else                                                                                                                   
	--                              dst_device = GetDeviceName(dst_vlan)                                                                           
	--                      end                                                                                                                 
	--                      local device_name = x:get("dreamcatcher",IcName,"device_name")                                                         
	--                      if device_name == nil then                                                                                          
	--                              device_name = "Unknown device"                                                                                 
	--                      end                                                                                                                 
	--                      local type = x:get("dreamcatcher",IcName,"type")                                                                       
	--                      local message = GetTitle(src_device,dst_device,device_name,type)                                                
	--                      --local message = x:get("dreamcatcher",IcName,"message")                                                               
	--                      permanent_table = permanent_table .. "<td>" .. message .. "</td>\n"                                                    
	--                      local verdict = x:get("dreamcatcher",IcName,"verdict")                                                                 
	--                      if verdict ~= nil then                                                                                                 
	--                              permanent_table = permanent_table .. "<td>" .. verdict .. "</td>\n"                                            
	--                      else                                                                                                                   
	--                              permanent_table = permanent_table .. "<td></td>\n"                                                             
	--                      end                                                                                                                    
	--                      permanent_table = permanent_table                                                                               
	--                              .. '<td><form style="margin:0px;display: inline" id="' .. IcName .. "delete" .. '" action="" method="POST">'   
	--                              .. '<input type="hidden" name="delete" value="' .. IcName .. '"></input>'                                   
	--                              .. '<input type="button" onclick="modify_rule_2(\'' .. IcName .. '\',\'delete\')" value="Delete"></input>'       
	--                              .. '</form></td>'                                                                                           
	--                      permanent_table = permanent_table .. "</tr>"                                                                        
	--              end                                                                                                                         
	--      end                                                                                                                                 
	--      )
	permanent_table = permanent_table .. "</table>"
	if flag == true then
		return permanent_table
	else
		return "<table style=\"width=100%;margin:0px\"><tr><td>Currently no rules</td></tr></table>"                                                                      
	end
end

function general_temp_rule_table()
	local x = luci.model.uci.cursor()                                                                                              
	local flag = false                                                                               
	local temp_table = '<table style="width:100%;margin:0px">' ..                                                                  
	"<tr>" ..                                                                                        
	"<td>Message</td>" ..                                                                                                  
	"<td width=\"150\"<td>" ..                                                                                             
	"</tr>"
	x:foreach("dreamcatcher","rule",function(s)
		local IcName = s[".name"]
		local approved = x:get("dreamcatcher",IcName,"approved")
		if approved == "0" then
			flag = true
			temp_table = temp_table .. "<tr>\n"
			local src_device = ""
			local dst_device = ""
			local device_name = ""
			local src_vlan = x:get("dreamcatcher",IcName,"src_vlan")
			if src_vlan == nil then
				src_device = "Unknown device"
			else
				src_device = GetDeviceName(src_vlan)
			end
			local dst_vlan = x:get("dreamcatcher",IcName,"dst_vlan")
			if dst_vlan == nil then
				dst_device = "Unknown device"
			else
				dst_device = GetDeviceName(dst_vlan)
			end
			local device_names = x:get("dreamcatcher",IcName,"device_name")
			if device_names == nil then
				device_names = "Unknown device"
			end
			local type = x:get("dreamcatcher",IcName,"type")
			if type == "3" then -- if this is an advertisement, we're going to display multiple rules
				for k,device_name in pairs(device_names) do
					local message = GetTitle(src_device,dst_device,device_name,type)
					--local message = x:get("dreamcatcher",IcName,"message")                                                                                                                              
					temp_table = temp_table .. "<td>" .. message .. "</td>\n" 			
					temp_table = temp_table .. "<td>"                                                                              
					.. '<form style="margin:0px;display:inline" id="' .. IcName .. "accept" .. '" action="" method="POST">'
					.. '<input type="hidden" name="accept" value="' .. IcName .. '"></input>'                              
					.. '<input type="submit" value="Accept"></input>'
					.. '</form>'                                                                                           
					.. '<form style="margin:0px;display:inline" id="' .. IcName .. "reject" .. '" action="" method="POST">'
					.. '<input type="hidden" name="reject" value="' .. IcName .. '"></input>'                              
					.. '<input type="submit" value="Reject"></input>'
					.. '</form>'                                                                                           
					.. '<form style="margin:0px;display:inline" id="' .. IcName .. "delete" .. '" action="" method="POST">'
					.. '<input type="hidden" name="delete" value="' .. IcName .. '"></input>'                              
					.. '<input type="submit" value="Delete"></input>'
					.. '</form></td>'                                                                                      
					temp_table = temp_table .. "</tr>"
				end
			else
				local message = GetTitle(src_device,dst_device,device_name,type)
				--local message = x:get("dreamcatcher",IcName,"message")                                                                                                                              
				temp_table = temp_table .. "<td>" .. message .. "</td>\n" 			
				temp_table = temp_table .. "<td>"                                                                              
				.. '<form style="margin:0px;display:inline" id="' .. IcName .. "accept" .. '" action="" method="POST">'
				.. '<input type="hidden" name="accept" value="' .. IcName .. '"></input>'                              
				.. '<input type="submit" value="Accept"></input>'
				.. '</form>'                                                                                           
				.. '<form style="margin:0px;display:inline" id="' .. IcName .. "reject" .. '" action="" method="POST">'
				.. '<input type="hidden" name="reject" value="' .. IcName .. '"></input>'                              
				.. '<input type="submit" value="Reject"></input>'
				.. '</form>'                                                                                           
				.. '<form style="margin:0px;display:inline" id="' .. IcName .. "delete" .. '" action="" method="POST">'
				.. '<input type="hidden" name="delete" value="' .. IcName .. '"></input>'                              
				.. '<input type="submit" value="Delete"></input>'
				.. '</form></td>'                                                                                      
				temp_table = temp_table .. "</tr>"
			end
		end
	end)
	--x:foreach("dreamcatcher","dpi_rule",function(s)                                                         
	--              local IcName = s[".name"]                                                                   
	--              local approved = x:get("dreamcatcher",IcName,"approved")                                        
	--              if approved == "0" then                                                                         
	--                      flag = true                                                                         
	--                      temp_table = temp_table .. "<tr>\n"                                                 
	--                      local src_device = ""                                                               
	--                      local dst_device = ""                                                               
	--                      local device_name = ""                                                              
	--                      local src_vlan = x:get("dreamcatcher",IcName,"src_vlan")                            
	--                      if src_vlan == nil then                                                             
	--                              src_device = "Unknown device"                                               
	--                      else                                                                                
	--                              src_device = GetDeviceName(src_vlan)                                        
	--                      end                                                                                 
	--                      local dst_vlan = x:get("dreamcatcher",IcName,"dst_vlan")                            
	--                      if dst_vlan == nil then                                                             
	--                              dst_device = "Unknown device"                                               
	--                      else                                                                                
	--                              dst_device = GetDeviceName(dst_vlan)                                        
	--                      end                                                                                 
	--                      local device_name = x:get("dreamcatcher",IcName,"device_name")                      
	--                      if device_name == nil then                                                          
	--                              device_name = "Unknown device"                                              
	--                      end                                                                                 
	--                      local type = x:get("dreamcatcher",IcName,"type")                                    
	--                      local message = GetTitle(src_device,dst_device,device_name,type)                    
	--                      --local message = x:get("dreamcatcher",IcName,"message")                            
	--                      temp_table = temp_table .. "<td>" .. message .. "</td>\n"                           
	--                      temp_table = temp_table .. "<td>"                                                                              
	--                      	.. '<form style="margin:0px;display:inline" id="' .. IcName .. "accept" .. '" action="" method="POST">'
	--                      	.. '<input type="hidden" name="accept" value="' .. IcName .. '"></input>'                              
	--                      	.. '<input type="button" onclick="modify_rule_2(\'' .. IcName .. '\',\'accept\')" value="Accept"></input>'
	--                      	.. '</form>'                                                                                           
	--                      	.. '<form style="margin:0px;display:inline" id="' .. IcName .. "reject" .. '" action="" method="POST">'
	--                      	.. '<input type="hidden" name="reject" value="' .. IcName .. '"></input>'                              
	--                      	.. '<input type="button" onclick="modify_rule_2(\'' .. IcName .. '\',\'reject\')" value="Reject"></input>'
	--                      	.. '</form>'                                                                                           
	--                      	.. '<form style="margin:0px;display:inline" id="' .. IcName .. "delete" .. '" action="" method="POST">'
	--                      	.. '<input type="hidden" name="delete" value="' .. IcName .. '"></input>'                              
	--                      	.. '<input type="button" onclick="modify_rule_2(\'' .. IcName .. '\',\'delete\')" value="Delete"></input>'
	--                      	.. '</form></td>'                                                                                      
	--                      temp_table = temp_table .. "</tr>"                                                  
	--              end                                                                                         
	--      end)
	temp_table = temp_table .. "</table>"
	if flag == true then
		return temp_table
	else
		return "<table style=\"width=100%;margin:0px\"><tr><td>Currently no rules</td></tr></table>"
	end
end

function split_dash(str)
	fields = {}
	for text in string.gmatch(str, "[^-]+") do
		log.print("field: " .. text)
		table.insert(fields, text)
	end
	if #fields < 2 then
		fields[2] = ""
	end
	log.print("returning fields: " .. fields[1] .. " " .. fields[2])
	return fields[1], fields[2]
end

function delete_rule()
	log.print("form value: " .. http.formvalue("delete"))
	local delete_rule, device_idx = split_dash(http.formvalue("delete"))
	log.print("device_idx after split: " .. device_idx)
	local x=luci.model.uci.cursor()
	if device_idx == "" then -- normal case
		if(x:delete("dreamcatcher",delete_rule)) then
			x:commit("dreamcatcher")	
			os.execute("/sbin/fw3 reload-dreamcatcher")
		end
	else -- we have a type 3 rule with a device index, remove that device only!
		local device_names = x:get("dreamcatcher",delete_rule,"device_name")
		if device_names == nil then -- weird, no devices for this rule -- ignore index and remove rule
			if(x:delete("dreamcatcher",delete_rule)) then
				x:commit("dreamcatcher")	
				os.execute("/sbin/fw3 reload-dreamcatcher")
			end
		else -- we have a set of names -- remove the specified device index and commit
			log.print("device_idx: " .. device_idx)
			table.remove(device_names, device_idx)
			if next(device_names) == nil then -- if table is now empty, just delete the whole rule
				if(x:delete("dreamcatcher",delete_rule)) then
					x:commit("dreamcatcher")	
					os.execute("/sbin/fw3 reload-dreamcatcher")
				end
			else -- table still has some names, so commit the new one
				x:set("dreamcatcher",delete_rule,"device_name",device_names)
				x:commit("dreamcatcher")
				os.execute("/sbin/fw3 reload-dreamcatcher")
			end
		end
	end
end

function add_rule()
	local rule_type = http.formvalue("rule_type")
	local src_vlan = http.formvalue("src_vlan")
	local dst_vlan = http.formvalue("dst_vlan")
	local proto = http.formvalue("proto")
	local src_ip = http.formvalue("src_ip")
	local dst_ip = http.formvalue("dst_ip")
	local src_port = http.formvalue("src_port")
	local dst_port = http.formvalue("dst_port")
	local verdict = http.formvalue("verdict")
	local x = luci.model.uci.cursor()
	local src_device = ""
	local dst_device = ""
	if rule_type == "perm" then
		local string = "type" .. "0" .. "src_vlan" .. src_vlan .. "dst_vlan" .. dst_vlan .. "proto" .. proto .. "src_ip" .. src_ip
		.. "dst_ip" .. dst_ip .. "src_port" .. src_port .. "dst_port" .. dst_port
		--local name = GeneratePassword(16)
		local name = getMD5(string)
		x:set("dreamcatcher",name,"rule")
		if src_vlan ~= nil then                                                           
			src_device = GetDeviceName(src_vlan)                                      
		else                                                                              
			src_device = "Unknown device"                                             
		end
		if dst_vlan ~= nil then                                                           
			dst_device = GetDeviceName(dst_vlan)                                      
		else                                                                              
			dst_device = "unknown device"                                             
		end
		--x:set("dreamcatcher",name,"message",GetTitle(src_device,dst_device,type))
		if src_vlan ~= "" then
			x:set("dreamcatcher",name,"src_vlan",src_vlan)
		end
		if dst_vlan ~= "" then
			x:set("dreamcatcher",name,"dst_vlan",dst_vlan)                                                                         
		end
		if proto ~= "" then
			x:set("dreamcatcher",name,"proto",proto)                                                                         
		end
		if src_ip ~= "" then
			x:set("dreamcatcher",name,"src_ip",src_ip)                                                                         
		end
		if dst_ip ~= "" then
			x:set("dreamcatcher",name,"dst_ip",dst_ip)                                                                         
		end
		if src_port ~= "" then
			x:set("dreamcatcher",name,"src_port",src_port)                                                                         
		end
		if dst_port ~= "" then
			x:set("dreamcatcher",name,"dst_port",dst_port)                                                                         
		end
		if verdict ~= "" then
			x:set("dreamcatcher",name,"verdict",verdict)                                                                         
		end
		x:set("dreamcatcher",name,"type","0")
		x:set("dreamcatcher",name,"approved","1")
	else
		local string = "type" .. "0" .. "src_vlan" .. src_vlan .. "dst_vlan" .. dst_vlan .. "proto" .. proto .. "src_ip" .. src_ip  
		.. "dst_ip" .. dst_ip .. "src_port" .. src_port .. "dst_port" .. dst_port                                      
		--local name = GeneratePassword(16)                                                                                            
		local name = getMD5(string) 
		x:set("dreamcatcher",name,"rule")                                                                         
		if src_vlan ~= nil then                                                                   
			src_device = GetDeviceName(src_vlan)                                              
		else                                                                                      
			src_device = "Unknown device"                                                     
		end                                                                                       
		if dst_vlan ~= nil then                                                                   
			dst_device = GetDeviceName(dst_vlan)                                              
		else                                                                                      
			dst_device = "Unknown device"                                                     
		end                                                                                       
		--x:set("dreamcatcher",name,"message",GetTitle(src_device,dst_device,type))
		if src_vlan ~= "" then                                                                                                 
			x:set("dreamcatcher",name,"src_vlan",src_vlan)                                                                 
		end                                                                                                                    
		if dst_vlan ~= "" then                                                                                                 
			x:set("dreamcatcher",name,"dst_vlan",dst_vlan)                                                                 
		end                                                                                                                    
		if proto ~= "" then                                                                                                    
			x:set("dreamcatcher",name,"proto",proto)                                                                       
		end                                                                                                                    
		if src_ip ~= "" then                                                                                                   
			x:set("dreamcatcher",name,"src_ip",src_ip)                                                                     
		end                                                                                                                    
		if dst_ip ~= "" then                                                                                                   
			x:set("dreamcatcher",name,"dst_ip",dst_ip)                                                                     
		end                                                                                                                    
		if src_port ~= "" then                                                                                                 
			x:set("dreamcatcher",name,"src_port",src_port)                                                                 
		end                                                                                                                    
		if dst_port ~= "" then                                                                                                 
			x:set("dreamcatcher",name,"dst_port",dst_port)                                                                 
		end                                                                                                                    
		if verdict ~= "" then                                                                                                  
			x:set("dreamcatcher",name,"verdict",verdict)                                                                   
		end
		x:set("dreamcatcher",name,"type","0")
		x:set("dreamcatcher",name,"approved","0")    	
	end
	x:commit("dreamcatcher")
	os.execute("/sbin/fw3 reload-dreamcatcher")
end

function add_devices()
	local dname = http.formvalue("device_name")
	if valid_username(dname) == false then
		luci.template.render("admin_security/password",{
			TODO = "<pre><span class=\"inner-pre\" style=\"font-size:20px\">Invalid device name. Only numbers, English alphabets, hyphens, and underscores are allowed.</span></pre>",
			table_text = GenerateTable()
		})
		return true	
	end                                                                                                                                               
	local file_read_1 = io.open("/etc/freeradius2/users","r+")                                                                                                                                
	local message = "";                                                                                                                                                                       
	local flag = true                                                                                                                                                                         
	for line in file_read_1:lines() do                                                                                                                                                        
		local s, e = string.find(line,dname,1,true)                                                                                                                                       
		if s == 2 then                                                                                                                                                                    
			if (line:sub(1,1) == '"' and line:sub(e+1,e+1) == '"') then                                                                                                               
				flag = false                                                                                                                                                      
			end                                                                                                                                                                       
		end                                                                                                                                                                               
	end                                                                                                                                                                                       
	file_read_1:close()                                                                                                                                                                       
	if flag == true then                                                                                                                                                                      
		--message = "<pre>valid</pre>"                                                                                                                                                    
		local password = GeneratePassword(16)                                                                                                                                             
		local GroupID = 100                                                                                                                                                                 
		while true do                                                                                                                                                                     
			local match_flag = true                                                                                                                                                   
			local templine = 'Tunnel-Private-Group-ID = "' .. tostring(GroupID) .. '"'                                                                                                
			local file_read_2 = io.open("/etc/freeradius2/users","r+")                                                                                                                
			for line in file_read_2:lines() do                                                                                                                                        
				local s, e = string.find(line,templine,1,true)                                                                                                                    
				if s ~= nil then                                                                                                                                                  
					match_flag = false                                                                                                                                        
					break                                                                                                                                                    
				end                                                                                                                                                             
				--message = message .. line .. "<br>" .. templine .. "<br>" .. tostring(s) .. "<br>" .. tostring(e) .. "<br>"                                                     
			end                                                                                                                                                                       
			file_read_2:close()                                                                                                                                                       
			if match_flag == true then                                                                                                                                                
				break                                                                                                                                                             
			else                                                                                                                                                                      
				GroupID = GroupID + 1                                                                                                                                             
			end                                                                                                                                                                       
		end                                                                                                                                                                               
		local file = io.open("/etc/freeradius2/users","a+")                                                                                                                               
		file:write('"' .. dname ..'"\tCleartext-Password := "' .. password .. '"\n')                                                                                                    
		file:write('\t\tTunnel-Type = "VLAN",\n')                                                                                                                                         
		file:write('\t\tTunnel-Medium-Type = "IEEE-802",\n')                                                                                                                              
		file:write('\t\tTunnel-Private-Group-ID = "' .. tostring(GroupID) .. '",\n')                                                                                                      
		file:write('\t\tReply-Message = "Hello, %{User-Name}",\n')                                                                                                                        
		file:write('\t\tFall-Through = Yes\n\n')                                                                                                                                            
		file:close()
		os.execute("killall radiusd") -- restart and reload not implemented 
		os.execute("/etc/init.d/radiusd start")                                                                                                                                                                      
		message = message .. '<pre><span class="inner-pre" style="font-size:20px">Device name: ' 
		.. dname ..  "<br><br>Password: " 
		.. password:sub(1,4) .. " "
		.. password:sub(5,8) .. " "
		.. password:sub(9,12) .. " "
		.. password:sub(13,16) 
		.. "<br><br>Group-ID: " .. tostring(GroupID)
		.. "<br><br>P.S. The password should not include spaces." 
		.. "</span></pre>"                                          
	else                                                                                                                                                                                      
		message = '<pre><span class="inner-pre" style="font-size:20px">Duplicate device name or resubmision of the same form</span></pre>'                                                                                                      
	end                                                                                                                                                                                       
	--luci.template.render("admin_security/password",{                                                                                                                                          
	--	TODO = message,                                                                                                                                                                   
	--    table_text = GenerateTable()                                                                                                                                                      
	--})
	return message
end

function GetDeviceName(vlan)                                                                                                           
	if vlan == nil then
		return "Unknown device"
	end
	local dname = ""                                                                                                               
	local vlan_line = 'Tunnel-Private-Group-ID = "' .. vlan  .. '"'                                                        
	local file = io.open("/etc/freeradius2/users","r")                                                                             
	for line in file:lines() do                                                                                                    
		if line:sub(1,1)=='"' then                                                                                              
			local templine =string.sub(line,2)                                                                             
			local e = string.find(templine,'"',1,true)                                                                     
			dname = string.sub(line,2,e)                                                                                   
		end                                                                                                                    
		local s,e = string.find(line,vlan_line,1,true)
		if s ~= nil then
			return dname	
		end                                                                                                                                       
	end
	return "Unknown device"                                                                                                                            
end  

function delete_devices()
	local dname = http.formvalue("delete_device")
	local file = io.open("/etc/freeradius2/users","r")
	local wfile = ""
	local temp = -1
	--log.print("Begin search device name")
	for line in file:lines() do
		if line:sub(1,1)=='"' then
			local templine = string.sub(line,2)
			local e = string.find(templine,'"',1,true)
			local name = string.sub(line,2,e)
			if dname==name then
				temp = 0
				--log.print("Found device name")
			end 
		end
		if(temp == -1 or temp == 7) then
			wfile = wfile .. line .. '\n'
		else 
			do
				if (temp == 3) then
					local s,e = string.find(line,'"',1,true)
					local subline = string.sub(line,s+1)
					s,e = string.find(subline,'"',1,true)
					local vlan = string.sub(subline,1,s-1)
					local x = luci.model.uci.cursor()
					--log.print("Found device's vlan")
					--log.print("Removing rule with same vlan")
					x:foreach("dreamcatcher","rule",function(s)
						local IcName = s[".name"]
						local src_vlan = x:get("dreamcatcher",IcName,"src_vlan")
						local dst_vlan = x:get("dreamcatcher",IcName,"dst_vlan")
						if (src_vlan == vlan or dst_vlan == vlan) then
							--log.print("Deleting rule " .. IcName)
							x:delete("dreamcatcher",IcName)
						end
					end)
					--log.print("Removed rule with same vlan")
					--log.print("Removing dpi_rule with same vlan")
					x:foreach("dreamcatcher","dpi_rule",function(s)                                                                                                               
						local IcName = s[".name"]                                                                   
						local src_vlan = x:get("dreamcatcher",IcName,"src_vlan")                                                                                          
						local dst_vlan = x:get("dreamcatcher",IcName,"dst_vlan")                                                                                                    
						if (src_vlan == vlan or dst_vlan == vlan) then                                                                                                    
							--log.print("Deleting dpi rule" .. IcName)
							x:delete("dreamcatcher",IcName)                                               
						end                                                                                                       
					end)
					--log.print("Removed dpi_rule with same vlan")
					--log.print("Begin commit to the dreamcatcher config file")
					x:commit("dreamcatcher") 
					--log.print("Commited dreamcatcher config file")
					--log.print("Restarting dreamcatcher config file")                                                                                                                                                                           
					os.execute("/sbin/fw3 reload-dreamcatcher")
					--log.print("Restarted dreamcatcher config file")	
				end	
				temp = temp + 1
			end	
		end	
	end
	file:close()
	--log.print("Open freeradius2 config file")
	local writefile = io.open("/etc/freeradius2/users","w")
	--log.print("Begin writing to the config file")
	writefile:write(wfile)
	--log.print("Finished writing to the config file")
	writefile:close()
	--log.print("Restarting freeradius2")
	os.execute("killall radiusd") -- restart and reload not implemented 
	os.execute("/etc/init.d/radiusd start")
	--log.print("Finished restarting freeradius2")
	luci.template.render("admin_security/password",{
		TODO = "",
		table_text = GenerateTable()
	})
end

function GeneratePassword(length)
	--math.randomseed(os.time())
	if length < 1 then return nil end
	local urandom = io.open("/dev/urandom","rb")
	local s = ""
	for i = 1, length do
		s = s .. GenerateChar()
	end
	return s
end

function GenerateChar()
	local urandom = io.open("/dev/urandom","rb")
	local temp = urandom:read(4)
	local Large_int = 0
	for i = 1, 4 do
		Large_int = temp:byte(i) + 256 * Large_int 
	end
	return string.char(97 + Large_int % 26) 
end

function valid_username(dname)
	local length = string.len(dname)
	if length < 1 then return false end
	for i = 1, length do
		local charnum = string.byte(dname,i)
		if (charnum < 45 or (charnum > 45 and charnum < 48) or (charnum > 57 and charnum < 65) or (charnum > 90 and charnum < 95) or (charnum == 96) or (charnum >122)) then
			return false
		end
	end
	return true
end

function GenerateTable()
	local table_text = '<table style="width:100%;margin:0px">\n'
	local file = io.open("/etc/freeradius2/users","r")
	local count = 0
	local flag = false
	for line in file:lines() do
		if line:sub(1,1)=='"' then
			flag = true
			count = count + 1
			local templine = string.sub(line,2)
			local e = string.find(templine,'"',1,true)
			local name = string.sub(line,2,e)
			local button = string.format('<tr>\n\t<td>%s</td>\n\t<td width="100"><form id="form%d" style="margin:0px" action="process" method="post"><input type="hidden" name="delete_device" value="%s"></input><input type="submit" value="Delete"></input></form></td>\n</tr>',name,count,name)
			table_text = table_text .. button .. "\n"
		end
	end
	file:close()
	if flag == false then
		table_text = "<table style=\"width=100%;margin:0px\"><tr><td>Currently no devices. Please add new devices</td></tr></table>"
	else
		table_text = table_text .. "\n</table>"
	end
	return table_text
end

function GetTitle(src_device,dst_device,device_name,type)
	if type == "0" then
		return src_device .. " wants to send messages to " .. dst_device
	elseif type == "1" then
		return src_device .. " wants to broadcast messages to your network"
	elseif type == "2" then
		return src_device .. " is trying to discover services on your network"
	elseif type == "3" then
		return src_device .. " wants to advertise itself on your network as " .. device_name
	else 
		return "Unknown Message"
	end	
end

function getMD5(string_input)
	local handle=io.popen("echo '" .. string_input .. "' -n | md5sum")
	local result=handle:read("*a")
	handle:close()
	local md5 = string.sub(result,1,32)
	return md5
end

function accept_all_rules()
	--log.print("Start accepting all rules")
	local x = luci.model.uci.cursor()
	x:foreach("dreamcatcher","rule",function(s)                                                                                                                             
		local IcName = s[".name"]                                                                                                                                                         
		local approved = x:get("dreamcatcher",IcName,"approved")
		if approved == '0' then
			x:set("dreamcatcher",IcName,"approved","1")
			x:set("dreamcatcher",IcName,"verdict","ACCEPT")
		end
	end)
	x:foreach("dreamcatcher","dpi_rule",function(s)                                                                                                                                                         
		local IcName = s[".name"]                                                                                                    
		local approved = x:get("dreamcatcher",IcName,"approved")                                                                                                                                    
		if approved == '0' then                                                                                                                                             
			x:set("dreamcatcher",IcName,"approved","1")                                                                                       
			x:set("dreamcatcher",IcName,"verdict","ACCEPT")                                                                     
		end                                                                                                                                       
	end)
	x:commit("dreamcatcher")                                                                                                                                                                  
	os.execute("/sbin/fw3 reload-dreamcatcher")
	--log.print("End accepting all rules")
end

function GenerateLinks()                                                                                                                                                                                    
	local links = ""                                                                                                                                                                                    
	local x = luci.model.uci.cursor()                                                                                                                                                                   
	x:foreach("dreamcatcher","rule",function(s)                                                                                                                                                         
		local IcName = s[".name"]                                                                                                                                                                   
		local type = x:get("dreamcatcher",IcName,"type")                                                                                                                                            
		if type == "0" then                                                                                                                                                                         
			local src_vlan = x:get("dreamcatcher",IcName,"src_vlan")                                                                                                                            
			local dst_vlan = x:get("dreamcatcher",IcName,"dst_vlan")                                                                                                                            
			local src_device = GetDeviceName(src_vlan)                                                                                                                                          
			local dst_device = GetDeviceName(dst_vlan)                                                                                                                                          
			local approved = x:get("dreamcatcher",IcName,"approved")                                                                                                                            
			local verdict = x:get("dreamcatcher",IcName,"verdict")                                                                                                                              
			if (approved == "1" and verdict == "ACCEPT") then
				links = links .. "{source: \"" .. src_device .. "\", target: \"" .. dst_device .. "\", type: \"unicast_accept\"},\n"
			end                                                                                                                                                                                    
		end 
	end                                                                                                                                                                                        
	)                                                                                                                                                                                                   
	return links
end 

function GenerateNodes()
	local nodes = ""
	local file = io.open("/etc/freeradius2/users","r")                                                                                                                                                  
	for line in file:lines() do                                                                                                                                                                         
		if line:sub(1,1)=='"' then                                                                                                                                                                  
			local templine =string.sub(line,2)                                                                                                                                                  
			local e = string.find(templine,'"',1,true)                                                                                                                                          
			dname = string.sub(line,2,e) 
			nodes = nodes .. 'dname = "' .. dname .. '"\n' 
			.. 'dname = nodes[dname] || (nodes[dname] = {name : dname});\n'                                                                                                                                                      
		end                                                                                                                                                                                         
	end	
	return nodes
end

--log.print("Log end!")
--log.print("-------------------------------------------------------")
