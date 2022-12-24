local Consts = require'manager.consts'
local Toml = require'manager.lib.toml'

local M = {}

M.enumerate_scripts_in_path = function(path, is_not_root)
	local scripts = {} 

	--get files in directory
	local file_list = fs.list(path)

	-- check format
	local format = 'normal'
	for i,file in ipairs(file_list) do 
		--check if mod metadata file exists
		if is_not_root and (file == Consts.MOD_CONF_FILE) then
			format = 'mod'
			break
		elseif (not is_not_root) and (file == Consts.LEGACY_AUTORUN_FILE) then
			format = 'legacy'
			break
		end
	end

	--load things
	if format == 'normal' then
		for _,file in ipairs(file_list) do 
			local file_path = path..'/'..file
			if fs.isDirectory(file_path) then
				local subdir_scripts = M.enumerate_scripts_in_path(file_path, true)
				for _,script in ipairs(subdir_scripts) do
					scripts[#scripts+1] = script
				end
			elseif (
				(fs.isFile(file_path)) and 
				(str:sub(-4) == '.lua')
			) then
				scripts[#scripts + 1] = {
					format = 'file',
					id = file_path:gsub('%\\', '_'):gsub('%/', '_'):gsub('%.lua', ''),
					name = file,
					path = file_path,	
					dir_path = path,					
				}
			end
		end
	elseif format == 'mod' then
		--todo handle errors!
		local conf_file_path = path..'/'..Consts.MOD_CONF_FILE
		local file = io.open(conf_file_path, 'rb')
		local conf_file_data = file:read('*a')
		file:close()
		local configuration = Toml.parse(conf_file_data)
		local permissions = {}
		if configuration.no_sandbox then
			permissions.no_sandbox = true
		else
			for i,v in pairs(configuration.permissions or {}) do
				if type(i) == 'number' then
					permissions[v] = true
				else 
					permissions[i] = v
				end
			end
			for i,v in pairs(configuration.experimental or {}) do
				if type(i) == 'number' then
					permissions['compat_'..v] = true
				else 
					permissions['compat_'..i] = v
				end
			end
		end
		local entrypoint_path = path..'/'..configuration.mod.entrypoint:gsub('%.','/')..'.lua'
		scripts[#scripts+1] = {
			format = 'mod',
			dir_path = path,
			id = configuration.mod.id,	
			name = configuration.mod.name,
			author = configuration.mod.author,
			description = configuration.mod.description,		
			entrypoint = configuration.mod.entrypoint,
			entrypoint_file_path = entrypoint_path,
			permissions = permissions,
		}
	elseif format == 'legacy' then
		error('Cant load legacy mod directories yet')
	else
		error('Invalid mod directory format: '..tostring(format))
	end

	return scripts
end

return M
