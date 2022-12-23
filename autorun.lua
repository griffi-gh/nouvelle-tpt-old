local consts = require'manager.consts'
local loader = require'manager.loader'
local sandbox = require'manager.sandbox'

--Make sure that the manager is not loaded yet
assert(not _G['_'..consts.CODE_NAME], 'Already loaded')

--Create main struct
local manager = {}

function manager:init()
	sandbox.load_sandbox_helper()
	self:ensure_exists()
	self:reload_script_list()
	self:compile_script_entrypoints()
	self:run_compiled_scripts()
end

function manager:ensure_exists()
	if not fs.exists(consts.SCRIPTS_DIR) then 
		assert(fs.makeDirectory(consts.SCRIPTS_DIR), 'Failed to create script directory')
	end
end

function manager:reload_script_list()
	self.scripts = loader.enumerate_scripts_in_path(consts.SCRIPTS_DIR)
end

function manager:compile_script_entrypoints()
	for _,v in ipairs(self.scripts) do
		if v.format == 'mod' then
			local file, file_err = io.open(v.entrypoint_file_path, 'rb')
			if file_err and (not file) then
				tpt.throw_error('Script load error: \n'..file_err)
			else
				local code = file:read('*a')
				file:close()
				local box, compile_err = sandbox.sandbox(code, v.permissions, v.dir_path, v.id)
				if compile_err then
					tpt.throw_error('Script compile error: \n'..compile_err)
				else 
					v.sandbox = box
				end
			end
		else
			print('Mod format "'..v.format..'" is not executable')
		end
	end
end

function manager:run_compiled_scripts()
	for _,v in ipairs(self.scripts) do
		if v.sandbox then
			local result, err = v.sandbox()
			if (not result) and err then
				tpt.throw_error('Script runtime error: \n'..err)
			end
		end
	end
end

--Global
_G[consts.CODE_NAME] = {
	sandboxed = false,
	shared = sandbox.shared_table,
	permissions = { escape_sandbox = true },
	manager = manager
}

--Initialize
manager:init()
