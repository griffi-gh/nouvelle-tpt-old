--todos:
-- sandboxed/hooked events, sould stop after the script is disabled
-- 		- (should i hook all events or just unregiter them agter unload?)
-- auto-unregister elements
-- scoped filesystem
-- sandboxed loadstring
-- write path sznitize function/properly sanitize paths in require
-- capture print calls
--
--maybe:
-- should string.dump be allowed?
-- maybe proxy/wrap all external functions in the sandbox?
-- cancel http requests on unload
-- custom rng
-- if possible: safe setfenv implementation
--
--also:
-- do coroutines have metatables?

local Consts = require'manager.consts'
local Env = require'manager.sandbox.env'

local safeguard = 'assert('..Consts.CODE_NAME..'.sandboxed and _G["'..Consts.CODE_NAME..'"].sandboxed, "Not sandboxed properly, please report this issue immidiately");\t'

local Sandbox = {
	helper_loaded = false,
	shared_table = {},
	protected_list = {},
	safeguard = safeguard
}

Sandbox.sandbox = function(code, permissions, location, chunk_name, script_id)
	assert(code and permissions and script_id)

    chunk_name = chunk_name or script_id or 'sandboxed'
	
	if not permissions.no_sandbox then
		if code:byte(1) == 27 then
			return nil, "binary bytecode prohibited"
		end
		code = safeguard..code
	end

	local fn,err = loadstring(code, chunk_name)
	if not fn then return false,err end
		
	local env = {}
	if not permissions.no_sandbox then
		if not Sandbox.helper_loaded then
			error('Sandbox helper is not loaded')
		end

		if Sandbox.shared_table[script_id] then
			return false, "already running in sandbox"
		end
		Sandbox.shared_table[script_id] = {}
		env = Env.build_env({
			sandbox = Sandbox,
			permissions = permissions,
			script_dir = location,
			script_id = script_id,
			chunk_name = chunk_name,
		})
		fn = setfenv(fn, env)
	end

	local obj = {
		fn = fn,
		env = env,
		__call = function(self) return pcall(self.fn) end,
		unload = function(self)
			if type(self.env.on_before_unload) == 'function' then
				print('WARNING: on_before_unload api will be deprecated soon!')
				--before unload fn must be called inside the sandbox
				setfenv(self.env.on_before_unload, self.env)()
			end
			Sandbox.shared_table[script_id] = nil
		end
	}
	return setmetatable(obj, obj)
end

local function protect_helper(of, lock_writes)	
	if lock_writes == nil then lock_writes = true end
	local mt = getmetatable(of)
	Sandbox.protected_list[of] = true
	Sandbox.protected_list[mt] = true
	if lock_writes then
		mt.__newindex = function() error('Protected') end
	end
	mt.__metatable = 0
end

Sandbox.load_helper = function()
	assert(not Sandbox.helper_loaded, 'sandbox helper already loaded')
	Sandbox.helper_loaded = true
	protect_helper("")
	if socket then
		if socket.tcp then protect_helper(socket.tcp()) end
		if socket.udp then protect_helper(socket.udp()) end
		if socket.sink then protect_helper(socket.sink("close-when-done", socket.tcp())) end
		if socket.source then protect_helper(socket.source("until-closed", socket.tcp())) end
	end
	if http then
		protect_helper(http.get(''))
	end
	Sandbox.protected_list[string] = true
	Sandbox.protected_list[''] = true
	do
		local i = 0
		while sim.signs[i] do
			protect_helper(sim.signs[i], false)
			i = i + 1
		end
	end
end

return Sandbox
