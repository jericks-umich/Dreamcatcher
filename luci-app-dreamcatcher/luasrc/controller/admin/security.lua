module("luci.controller.admin.security",package.seeall)

local http = require("luci.http")
local protocol = require("luci.http.protocol")
local json = require("luci.json")


function index()
	entry({"admin","security"}, alias("admin","security","overview"),_("Security"),20).index = true
	entry({"admin","security","overview"}, template("admin_security/index"),_("Overview"),1)
	entry({"admin","security","process"},call("Device_page"),"Device",4).dependent=false
	entry({"admin","security","rule"}, firstchild(),"Rule",5).dependent=false
	entry({"admin","security","rule","rules_1"},call("Rule_General"),"General",6).dependent=false
	entry({"admin","security","rule","rules_2"},call("Rule_Advanced"),"Advanced",7).dependent=false
end

function Device_page()
	local http_method = http.getenv("REQUEST_METHOD")
	if http_method == "POST" then
		local dname = http.formvalue("device_name")
		local delete = http.formvalue("delete_device")
		if dname~=nil then
			add_devices()
		elseif delete ~= nil then
			delete_devices()
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

function Rule_General()                                 
        local http_method = http.getenv("REQUEST_METHOD")
        if http_method == "POST" then                  
                local delete = http.formvalue("delete")
                local accept = http.formvalue("accept")
                local reject = http.formvalue("reject")
                local src_vlan = http.formvalue("src_vlan")
		if delete~=nil then      
                        delete_rule()    
                elseif accept ~= nil then
                        accept_rule()    
                elseif reject ~= nil then
                        reject_rule()
                elseif src_vlan ~= nil then              
                        add_rule()
                end                                  
        end                                          
        luci.template.render("admin_security/rules",{
                permanent = general_perm_rule_table(),
                temp = general_temp_rule_table()
        })
end        

function Rule_Advanced()
	local http_method = http.getenv("REQUEST_METHOD")
	if http_method == "POST" then
		local delete = http.formvalue("delete")
		local accept = http.formvalue("accept")
		local reject = http.formvalue("reject")
		if delete~=nil then
			delete_rule()
		elseif accept ~= nil then
			accept_rule()
		elseif reject ~= nil then
			reject_rule()
		else
			add_rule()
		end
	end
	luci.template.render("admin_security/rules",{                                     
                permanent = advanced_perm_rule_table(),                                              
                temp = advanced_temp_rule_table()       
	}) 
end

function accept_rule()
	local accept_rule = http.formvalue("accept")
	local x = luci.model.uci.cursor()
	if (x:get("dreamcatcher",accept_rule,"approved")=="0") then
		x:set("dreamcatcher",accept_rule,"approved","1")
		x:set("dreamcatcher",accept_rule,"verdict","ACCEPT")
		x:commit("dreamcatcher")
	end
end

function reject_rule()
	local reject_rule = http.formvalue("reject")                                                                                   
        local x = luci.model.uci.cursor()                                                                                              
        if (x:get("dreamcatcher",reject_rule,"approved")=="0") then                                                                        
                x:set("dreamcatcher",reject_rule,"approved","1")                                                                       
                x:set("dreamcatcher",reject_rule,"verdict","REJECT")                                                                   
                x:commit("dreamcatcher")                                                                                               
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
        	"<td>Verdict</td>" ..
		"<td></td>" ..
	"</tr>"
	x:foreach("dreamcatcher","rule",function(s)
		local IcName = s[".name"]
		local type = x:get("dreamcatcher",IcName,"approved")
		if type == "1" then
			flag = true
			local src_device = ""                                                                                          
                        local dst_device = ""
			permanent_table = permanent_table .. "<tr>"
			local src_vlan = x:get("dreamcatcher",IcName,"src_vlan")
			if src_vlan ~= nil then
				src_device = GetDeviceName(src_vlan)
			else
				src_device = "Unknown device"
			end
			local dst_vlan = x:get("dreamcatcher",IcName,"dst_vlan")
			if dst_vlan ~= nil then
				dst_device = GetDeviceName(dst_vlan)
			else
				dst_device = "unknown device"
			end
			local title = x:get("dreamcatcher",IcName,"title")
			permanent_table = permanent_table .. "<td>" .. GetTitle(src_device,dst_device,title) .. "</td>\n"
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
                                .. '<input type="button" onclick="modify_rule(\'' .. IcName .. '\',\'delete\')" value="Delete"></input>'
                                .. '</form></td>'
			permanent_table = permanent_table .. "</tr>"
		end
	end
	)
	permanent_table = permanent_table .. "</table>"
	if flag == true then
		return permanent_table
	else	
		return 'Currently no rules' 
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
		local type = x:get("dreamcatcher",IcName,"approved")
		if type == "0" then
			flag = true
                	temp_table = temp_table .. "<tr>\n"                                         
                	local src_device = ""
			local dst_device = ""
			local src_vlan = x:get("dreamcatcher",IcName,"src_vlan")
			if src_vlan ~= nil then                                                                                                        
                		src_device = GetDeviceName(src_vlan)                                                                             
                	else
				src_device = "Unknown device"                                                                                                                   
        		end                                                                                                                           
        		local dst_vlan = x:get("dreamcatcher",IcName,"dst_vlan")                                                                       
        		if dst_vlan ~= nil then                                                                                                        
                		dst_device = GetDeviceName(dst_vlan)                                                                             
        		else                                                                                                                           
       				dst_device = "unknown device"
			end
			local title = x:get("dreamcatcher",IcName,"title")
			temp_table = temp_table .. "<td>" .. GetTitle(src_device,dst_device,title) .. "</td>\n"
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
                                .. '<input type="button" onclick="modify_rule(\'' .. IcName .. '\',\'accept\')" value="Accept"></input>'          
                                .. '</form>'
				.. '<form style="margin:0px;display:inline" id="' .. IcName .. "reject" .. '" action="" method="POST">'                    
                                .. '<input type="hidden" name="reject" value="' .. IcName .. '"></input>'                              
                                .. '<input type="button" onclick="modify_rule(\'' .. IcName .. '\',\'reject\')" value="Reject"></input>'          
                                .. '</form>'
				.. '<form style="margin:0px;display:inline" id="' .. IcName .. "delete" .. '" action="" method="POST">'
				.. '<input type="hidden" name="delete" value="' .. IcName .. '"></input>' 
				.. '<input type="button" onclick="modify_rule(\'' .. IcName .. '\',\'delete\')" value="Delete"></input>' 
				.. '</form></td>'
			temp_table = temp_table .. "</tr>" 
		end                                                                          
	end                                                                               
        )
	temp_table = temp_table .. "</table>" 
	if flag == true then
		return temp_table
	else 
                return 'Currently no rules'                                                      
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
		local type = x:get("dreamcatcher",IcName,"approved")
		if type == "1" then
			flag = true
			local src_device = ""
			local dst_device = ""
			permanent_table = permanent_table .. "<tr>"
			local src_vlan = x:get("dreamcatcher",IcName,"src_vlan")
                        if src_vlan ~= nil then                                 
                                src_device = GetDeviceName(src_vlan)            
                        else                                                    
                                src_device = "Unknown device"                   
                        end                                                     
                        local dst_vlan = x:get("dreamcatcher",IcName,"dst_vlan")                                         
                        if dst_vlan ~= nil then                                                                          
                                dst_device = GetDeviceName(dst_vlan)                                                     
                        else                                                                                             
                                dst_device = "unknown device"                                                            
                        end                                                                                              
                        local title = x:get("dreamcatcher",IcName,"title")                                               
                        permanent_table = permanent_table .. "<td>" .. GetTitle(src_device,dst_device,title) .. "</td>\n"
			local verdict = x:get("dreamcatcher",IcName,"verdict")                                           
                        if verdict ~= nil then                                                                           
                                permanent_table = permanent_table .. "<td>" .. verdict .. "</td>\n"                      
                        else                                                                                             
                                permanent_table = permanent_table .. "<td></td>\n"                
                        end
			permanent_table = permanent_table                                           
                                .. '<td><form style="margin:0px;display: inline" id="' .. IcName .. "delete" .. '" action="" method="POST">'
                                .. '<input type="hidden" name="delete" value="' .. IcName .. '"></input>'                              
                                .. '<input type="button" onclick="modify_rule(\'' .. IcName .. '\',\'delete\')" value="Delete"></input>'
                                .. '</form></td>'                                                                                      
                        permanent_table = permanent_table .. "</tr>" 
		end
	end
	)
	permanent_table = permanent_table .. "</table>"
	if flag == true then
		return permanent_table
	else
		return "Currently no rules"
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
		local type = x:get("dreamcatcher",IcName,"approved")
		if type == "0" then
			flag = true
			temp_table = temp_table .. "<tr>\n"
                        local src_device = ""                                                                                          
                        local dst_device = ""                                                                                          
                        local src_vlan = x:get("dreamcatcher",IcName,"src_vlan")                                                       
                        if src_vlan ~= nil then                                                                                        
                                src_device = GetDeviceName(src_vlan)                                                                   
                        else                                                                                                           
                                src_device = "Unknown device"                                                                          
                        end                                                                                                            
                        local dst_vlan = x:get("dreamcatcher",IcName,"dst_vlan")                                                       
                        if dst_vlan ~= nil then                                                                                        
                                dst_device = GetDeviceName(dst_vlan)                                                                   
                        else                                                                                                           
                                dst_device = "unknown device"                                                                          
                        end                                                                                                            
                        local title = x:get("dreamcatcher",IcName,"title")                                                             
                        temp_table = temp_table .. "<td>" .. GetTitle(src_device,dst_device,title) .. "</td>\n"  
			temp_table = temp_table .. "<td>"                                                                              
                                .. '<form style="margin:0px;display:inline" id="' .. IcName .. "accept" .. '" action="" method="POST">'
                                .. '<input type="hidden" name="accept" value="' .. IcName .. '"></input>'                              
                                .. '<input type="button" onclick="modify_rule(\'' .. IcName .. '\',\'accept\')" value="Accept"></input>'
                                .. '</form>'                                                                                           
                                .. '<form style="margin:0px;display:inline" id="' .. IcName .. "reject" .. '" action="" method="POST">'
                                .. '<input type="hidden" name="reject" value="' .. IcName .. '"></input>'                              
                                .. '<input type="button" onclick="modify_rule(\'' .. IcName .. '\',\'reject\')" value="Reject"></input>'
                                .. '</form>'                                                                                           
                                .. '<form style="margin:0px;display:inline" id="' .. IcName .. "delete" .. '" action="" method="POST">'
                                .. '<input type="hidden" name="delete" value="' .. IcName .. '"></input>'                              
                                .. '<input type="button" onclick="modify_rule(\'' .. IcName .. '\',\'delete\')" value="Delete"></input>'
                                .. '</form></td>'                                                                                      
                        temp_table = temp_table .. "</tr>"
		end
	end)
	temp_table = temp_table .. "</table>"
	if flag == true then
		return temp_table
	else
		return "Currently no rules"
	end
end

function delete_rule()
	local delete_rule = http.formvalue("delete")
	local x=luci.model.uci.cursor()
	if(x:delete("dreamcatcher",delete_rule)) then
		x:commit("dreamcatcher")	
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
	local title = http.formvalue("title")
	local x = luci.model.uci.cursor()
	if rule_type == "perm" then
		local name = GeneratePassword(16)
		x:set("dreamcatcher",name,"rule")
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
		if title ~= "" then
			x:set("dreamcatcher",name,"title",title)
		else
			x:set("dreamcatcher",name,"title","0")
		end
		x:set("dreamcatcher",name,"approved","1")
	else
		local name = GeneratePassword(16)
		x:set("dreamcatcher",name,"rule")                                                                         
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
		if title ~= "" then                                                                                           
                        x:set("dreamcatcher",name,"title",title)                                         
                else                                                                                                          
                        x:set("dreamcatcher",name,"title","0")                                                                
                end   
		x:set("dreamcatcher",name,"approved","0")    	
	end
	x:commit("dreamcatcher")
end

function add_devices()
	local dname = http.formvalue("device_name")
	if valid_username(dname) == false then
		luci.template.render("admin_security/password",{
			TODO = "<pre>Invalid device name. Only numbers and English alphabets are allowed.</pre>",
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
                local GroupID = 1                                                                                                                                                                 
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
                message = message .. "<pre>Device name: " .. dname ..  "<br>Password: " .. password .. "<br>Group-ID: " .. tostring(GroupID) .. "</pre>"                                          
	else                                                                                                                                                                                      
                message = "<pre>Duplicate device name or resubmision of the same form</pre>"                                                                                                      
        end                                                                                                                                                                                       
        luci.template.render("admin_security/password",{                                                                                                                                          
        	TODO = message,                                                                                                                                                                   
                table_text = GenerateTable()                                                                                                                                                      
        })
end

function GetDeviceName(vlan)                                                                                                           
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
	for line in file:lines() do
		if line:sub(1,1)=='"' then
			local templine = string.sub(line,2)
			local e = string.find(templine,'"',1,true)
			local name = string.sub(line,2,e)
			if dname==name then
				temp = 0
			end 
		end
		if(temp == -1 or temp == 7) then
			wfile = wfile .. line .. '\n'
		else
			temp = temp + 1	
		end	
	end
	file:close()
	local writefile = io.open("/etc/freeradius2/users","w")
	writefile:write(wfile)
	writefile:close()
	luci.template.render("admin_security/password",{
		TODO = "",
		table_text = GenerateTable()
	})
end

function GeneratePassword(length)
	math.randomseed(os.time())
	if length < 1 then return nil end
	local s = ""
	for i = 1, length do
		n = math.random(97,122)
		s = s .. string.char(n)
	end
	return s
end

function valid_username(dname)
	local length = string.len(dname)
	if length < 1 then return false end
	for i = 1, length do
		local charnum = string.byte(dname,i)
		if (charnum < 48 or (charnum > 57 and charnum < 65) or (charnum > 90 and charnum < 97) or (charnum >122)) then
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
			local button = string.format('<tr>\n\t<td>%s</td>\n\t<td><form id="form%d" style="margin:0px" action="process" method="post"><input type="hidden" name="delete_device" value="%s"></input><input type="submit" value="Delete"></input></form></td>\n</tr>',name,count,name)
			table_text = table_text .. button .. "\n"
		end
	end
	file:close()
	if flag == false then
		table_text = "Currently no devices. Please add new devices"
	else
		table_text = table_text .. "\n</table>"
	end
	return table_text
end

function GetTitle(src_vlan,dst_vlan,title)
	if title == "0" then
		return src_vlan .. " wants to communicate with " .. dst_vlan
	elseif title == "1" then
		return src_vlan .. " wants to discover devices on your network"
	elseif title == "2" then
		return src_vlan .. " wants to tell other devices on your network about itself"
	elseif title == "3" then
		return src_vlan .. " wants to broadcast to your network"
	else 
		return "Unknown title"
	end	
end