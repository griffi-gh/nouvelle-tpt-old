local consts = require'manager.consts'
local loader = require'manager.loader'
local sandbox = require'manager.sandbox'

--Make sure that the manager is not loaded yet
assert(not _G['_'..consts.CODE_NAME], 'Already loaded')

--Create main struct
local manager = {}
function manager:init()
	--load sandbox helper (locks metatables)
	sandbox.load_sandbox_helper()
	--make sure script directory exists
	if not fs.exists(consts.SCRIPTS_DIR) then 
		assert(fs.makeDirectory(consts.SCRIPTS_DIR), 'Failed to create script directory')
	end
	self:reload_script_list()
end
function manager:reload_script_list()
	self.scripts = loader.enumerate_scripts_in_path(consts.SCRIPTS_DIR)
end

--Global
_G[consts.CODE_NAME] = {
	sandboxed = false,
}

--Initialize
manager:init()
