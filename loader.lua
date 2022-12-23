local consts = require'manager.consts'

local M = {}

M.enumerate_scripts_in_path = function(path, is_not_root)
	local scripts = {} 

	--get files in directory
	local file_list = fs.list(path)

	-- check format
	local format = 'normal'
	for i,file in ipairs(file_list) do 
		--check if mod metadata file exists
		if is_not_root and (file == consts.MOD_CONF_FILE) then
			format = 'mod'
			break
		elseif (not is_not_root) and (file == consts.LEGACY_AUTORUN_FILE) then
			format = 'legacy'
			break
		end
	end

	--load things
	if format == 'normal' then
		for _,file in ipairs(file_list) do 
			local file_path = path..'/'..file
			if fs.isDirectory(file_path) then
				local subdir_scripts = enumerate_scripts_in_path(file_path, true)
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
				}
			end
		end
	elseif format == 'mod' then
		scripts[#scripts+1] = {
			format = 'mod',
			name = 'mod-directory-'..path,
			dir_path = path,
		}
	elseif format == 'legacy' then
		error('Cant load legacy mod directories yet')
	else
		error('Invalid mod directory format: '..tostring(format))
	end

	return scripts
end

return M
