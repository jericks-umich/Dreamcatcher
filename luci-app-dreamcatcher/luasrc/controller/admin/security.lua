module("luci.controller.admin.security",package.seeall)

local http = require("luci.http")
local protocol = require("luci.http.protocol")
local json = require("luci.json")

function index()
	entry({"admin","security"}, alias("admin","security","overview"),_("Security"),20).index = true
	entry({"admin","security","overview"}, template("admin_security/index"),_("Overview"),1)
	entry({"admin","security","process"},call("TODO"),"TODO",4).dependent=false
end

function TODO()
	local http_method = http.getenv("REQUEST_METHOD")
	if http_method == "POST" then
		dname = http.formvalue("device_name")
		if dname~=nil then
			add_devices()
		else
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
	local table_text = '<table style="width:100%">\n'
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
			local button = string.format('<tr>\n\t<td>%s</td>\n\t<td><form id="form%d" action="process" method="post"><input type="hidden" name="delete_device" value="%s"></input><input type="submit" value="Delete"></input></form></td>\n</tr>',name,count,name)
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
