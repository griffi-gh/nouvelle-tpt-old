--todos:
-- sandboxed/hooked events, sould stop after the script is disabled
-- 		- (should i hook all events or just unregiter them agter unload?)
-- auto-unregister elements
-- scoped filesystem
-- sandboxed loadstring
-- load /init.lua in require
-- write path sznitize function/properly sanitize paths in require
--
-- also:
-- should string.dump be allowed?
-- maybe proxy/wrap all external functions in the sandbox?
-- cancel http requests on unload

local Consts = require'manager.consts'

local Sandbox = {
	helper_loaded = false,
	shared_table = {}
}

local function whitelist(of, keys)
	assert(of and keys)
	local cloned = {}
	for _,key in ipairs(keys) do
		if key then
			if (type(key) == 'table') and (type(key[1]) == 'string') and (key[2] ~= nil) then
				cloned[key[1]] = key[2]
			else
				cloned[key] = of[key]
			end
		end
	end
	return cloned
end

local function w_cond(of, key, cond)
	return { key, cond and of[key] or nil }
end

local protected_list = {}

Sandbox.sandbox = function(code, permissions, location, chunk_name, script_id)
	assert(code and permissions and script_id)

    chunk_name = chunk_name or script_id or 'sandboxed'

	local safeguard = 'assert('..Consts.CODE_NAME..'.sandboxed and _G["'..Consts.CODE_NAME..'"].sandboxed, "Not sandboxed properly, please report this issue immidiately");\t'
	
	if not permissions.no_sandbox then
		if code:byte(1) == 27 then
			return nil, "binary bytecode prohibited"
		end
		code = safeguard..code
	end

	local fn,err = loadstring(code, chunk_name)
	if not fn then return false,err end
	
	if not permissions.no_sandbox then
		if not Sandbox.helper_loaded then
			print('Sandbox helper is not loaded, metatable permissions are unsafe witout it and therefore will be disabled!')
			permissions.compat_metatable = false
			permissions.compat_metatable_set = false
			permissions.compat_metatable_get = false
			permissions.compat_metatable_raw = false
		end

		if Sandbox.shared_table[script_id] then
			return false, "already running in sandbox"
		end
		Sandbox.shared_table[script_id] = {}

		local permissions_clone = {}
		for i,v in pairs(permissions) do
			permissions_clone[i] = v
		end
		--this is not actually required
		setmetatable(permissions_clone, { __newindex = function()end }) 
	
		local env = {
			_VERSION = _VERSION,
			print = print,
			type = type,
			error = error,
			assert = assert,
			ipairs = ipairs,
			pairs = pairs,
			next = next,
			select = select,
			tonumber = tonumber,
			tostring = tostring,			
			xpcall = xpcall,
			pcall = pcall,
			unpack = unpack or table.unpack,
			setmetatable = permissions.compat_metatable_set and (function(table, mt)
				assert((type(mt) == 'table') and (type(table) == 'table'), 'Bad arguments')
				assert(not(protected_list[table] or protected_list[mt]), 'Protected')
				return setmetatable(table, mt)
			end) or nil,
			getmetatable = permissions.compat_metatable_get and (function(table)
				assert(type(table) == 'table', 'Bad arguments')
				local mt = getmetatable(table)
				assert(not(protected_list[table] or protected_list[mt]), 'Protected')
				return mt
			end) or nil,
			rawget = permissions.compat_metatable_raw and rawget or nil,
			rawset = permissions.compat_metatable_raw and rawset or nil,
			rawequal = permissions.compat_metatable_raw and rawequal or nil,
			coroutine = whitelist(coroutine, {
				'create', 'resume', 'running', 'status', 
				'wrap', 'yield',
			}),
			string = whitelist(string, {
				'byte', 'char', 'find', 'format',
				'gmatch', 'gsub', 'len', 'lower', 
				'match', 'rep', 'reverse', 'sub',
				'upper',
			}),
			table = whitelist(table, {
				'insert', 'maxn', 'remove', 'sort', 'concat',
				{'unpack', unpack or table.unpack},
			}),
			math = whitelist(math, {
				w_cond(math, 'randomseed', permissions.compat_randomseed),
				'abs', 'acos', 'asin', 'atan', 'atan2', 
				'ceil', 'cos', 'cosh', 'deg', 'exp', 
				'floor', 'fmod', 'frexp', 'huge', 'ldexp', 
				'log', 'log10', 'max', 'min', 'modf',
				'pi', 'pow', 'rad', 'random', 'sin', 
				'sinh', 'sqrt', 'tan', 'tanh',
			}),
			io = whitelist(io, {
				w_cond(io, 'open', permissions.filesystem),
				'read', 'write', 'flush', 'type',
			}),
			os = whitelist(os, {
				w_cond(os, 'exit', permissions.exit),
				w_cond(os, 'getenv', permissions.env),
				w_cond(os, 'remove', permissions.filesystem),
				w_cond(os, 'rename', permissions.filesystem),
				w_cond(os, 'tmpname', permissions.filesystem),
				'clock', 'date', 'difftime', 'time',
			}),
			
			--used by sandboxed require, does not behave exactly like real _G.package
			package = {
				loaded = {},
				preload = {},
			},

			--luajit specific

			--powder toy functions
			tpt = setmetatable(whitelist(tpt, {
				{'version', whitelist(tpt.version, {
					'jacob1s_mod', 'major', 'minor',
				})},
				w_cond(tpt, 'set_pause', permissions.simulation_settings),
				w_cond(tpt, 'heat', permissions.simulation_settings),
				w_cond(tpt, 'ambient_heat', permissions.simulation_settings),
				w_cond(tpt, 'newtonian_gravity', permissions.simulation_settings),
				--todo more legacy apis
			}), {
				__index = function(self, i)
					if ({
						brushx = true,
						brushy = true,
						selectedl = true,
						selectedr = true,
						selecteda = true,
						selectedreplace = true,
						brushID = true,
					})[i] then
						return tpt[i]
					end
				end
			}),
			fs = whitelist(fs, {
				w_cond(fs, 'list', permissions.filesystem),
				w_cond(fs, 'exists', permissions.filesystem),
				w_cond(fs, 'isFile', permissions.filesystem),
				w_cond(fs, 'isDirectory', permissions.filesystem),
				w_cond(fs, 'makeDirectory', permissions.filesystem),
				w_cond(fs, 'removeFile', permissions.filesystem),
				w_cond(fs, 'removeDirectory', permissions.filesystem),
				w_cond(fs, 'move', permissions.filesystem),
				w_cond(fs, 'copy', permissions.filesystem),
			}),
			graphics = whitelist(graphics, {
				'textSize', 'getColors', 'getHexColor', 
				w_cond(fs, 'drawText', permissions.graphics),
				w_cond(fs, 'drawLine', permissions.graphics),
				w_cond(fs, 'drawRect', permissions.graphics),
				w_cond(fs, 'fillRect', permissions.graphics),
				w_cond(fs, 'drawCircle', permissions.graphics),
				w_cond(fs, 'fillCircle', permissions.graphics),
			}),
			socket = whitelist(socket, {
				'_VERSION', '_DEBUG', 'gettime', 'sleep',
				'try', 'protect', 'newtry', 'skip',
				w_cond(fs, 'tcp', permissions.internet),
				w_cond(fs, 'udp', permissions.internet),
				w_cond(fs, 'sink', permissions.internet),
				w_cond(fs, 'select', permissions.internet),
				w_cond(fs, 'source', permissions.internet),
				--dns is missing!
			}),
			simulation = whitelist(sim, {
				'DECO_DIVIDE', 'DECO_SMUDGE', 'DECO_ADD', 'DECO_SUBTRACT', 
				'DECO_CLEAR', 'DECO_DRAW', 'DECO_MULTIPLY', 'FIELD_DCOLOUR', 
				'FIELD_Y', 'FIELD_TEMP', 'FIELD_TYPE', 'FIELD_VY', 'FIELD_X', 
				'FIELD_TMP2', 'FIELD_TMP', 'FIELD_FLAGS', 'FIELD_VX', 'FIELD_CTYPE', 
				'FIELD_LIFE', 'MAX_TEMP', 'MIN_TEMP', 'NUM_PARTS', 'PT_NUM', 
				'R_TEMP', 'TOOL_VAC', 'TOOL_AIR', 'TOOL_NGRV', 'TOOL_PGRV', 
				'TOOL_HEAT', 'TOOL_WIND', 'TOOL_COOL', 'YRES', 'XRES',
				w_cond(tpt, 'waterEqualisation', permissions.simulation_settings),
				w_cond(tpt, 'gravityMode', permissions.simulation_settings),
				w_cond(tpt, 'airMode', permissions.simulation_settings),
				w_cond(tpt, 'edgeMode', permissions.simulation_settings),
				w_cond(tpt, 'prettyPowders', permissions.simulation_settings),
			}),
			renderer = whitelist(ren, {
				--permissions.render_settings
			}),
			event = whitelist(evt, {
				
			}),
			bit = whitelist(bit, {
				'tobit', 'tohex', 'bnot', 'band',
				'bor', 'bxor', 'lshift', 'rshift',
				'arshift', 'rol', 'ror', 'bswap',
			}),
			http = whitelist(http, {
				w_cond(http, 'get', permissions.internet),
				w_cond(http, 'post', permissions.internet),
			}),
			elem = elem, --TODO!!! HACK!!! USE WHITELIST!!!
		}

		--globals
		env._G = env
		env._ENV = env

		--aliases
		env.sim = env.simulation
		env.gfx = env.graphics
		env.ren = env.renderer
		env.evt = env.event

		--information
		env[Consts.CODE_NAME] = {
			sandboxed = true,
			permissions = permissions_clone,
			shared = Sandbox.shared_table[script_id],
			shared_of = function(mod_id)
				return Sandbox.shared_table[tostring(mod_id)] or nil
			end
		}

		--sandboxed require
		env.require = function(path)
			assert(location, 'Sandboxed script tried to use `require` but has unknown location')
			print('require '..path)
			
			--normalize path
			local normalized_req_path = path:gsub('%/','.'):gsub('%~', ''):gsub('%:','')
			while normalized_req_path:sub(1,1) == '.' do
				normalized_req_path = normalized_req_path:sub(2, #normalized_req_path)
			end
			while normalized_req_path:sub(-1) == '.' do
				normalized_req_path = normalized_req_path:sub(1, #normalized_req_path - 1)
			end

			--check package.loaded
			do
				local loaded = env.package.loaded[normalized_req_path]
				if loaded ~= nil then
					return loaded
				end
			end

			--check package.preload
			do 
				local preload = env.package.preload[normalized_req_path]
				if type(preload) == 'function' then
					return setfenv(preload, env)()
				end
			end

			--load package from file
			do
				local req_lua_file_path_base = location..'/'..normalized_req_path:gsub('%.', '/')
	
				local req_lua_file_path,ld_code
				do
					req_lua_file_path = req_lua_file_path_base..'/init.lua'
					local file,err = io.open(req_lua_file_path, 'rb')
					if file and not(err) then
						ld_code = file:read('*a')
						file:close()
					else
						req_lua_file_path = req_lua_file_path_base..'.lua'
						local file = assert(io.open(req_lua_file_path, 'rb'))
						ld_code = file:read('*a')
						file:close()
					end
				end

				if ld_code:byte(1) == 27 then
					return error("binary bytecode prohibited")
				end
				ld_code = safeguard..ld_code
				local fn = assert(loadstring(ld_code, chunk_name..':'..path))
				local sboxed_fn = setfenv(fn, env)
				local raw_result = {sboxed_fn()}
				local result = raw_result[1]
				if result == nil then
					result = false
				end
				env.package.loaded[normalized_req_path] = result
				return (unpack or table.unpack)(raw_result)
			end
		end

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

local function protect_helper(of)	
	local mt = getmetatable(of)
	protected_list[of] = true
	protected_list[mt] = true
	if type(of) == 'table' then of.__metatable = shared_lock end
	mt.__newindex = function() error('Protected') end
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
	protected_list[string] = true
	protected_list[''] = true
	--getmetatable(coroutine.create(function()end)).__metatable = ""
end

return Sandbox
