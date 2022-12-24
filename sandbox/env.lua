local Consts = require'manager.consts'

local Env = {}

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
	print('WARNING: deprecated w_cond sandboxing impl for '..key)
	return { key, cond and of[key] or nil }
end
local function w_perm_fn(key, perms, perm, value)
	return { key, perms[perm] and value or (function(...)
		if perm:sub(1,7) == 'compat_' then
			error('compatablity flag required: '..perm:sub(7-#perm))
		else
			error('permission required: '..perm)
		end
	end) }
end

Env.build_env = function(arg)
	local Sandbox = assert(arg.sandbox)
	local permissions = assert(arg.permissions)
	local script_id = assert(arg.script_id)
	local script_dir = arg.script_dir
	local chunk_name = arg.chunk_name
	
	local protected_list = Sandbox.protected_list

	local permissions_clone = {}
	for i,v in pairs(permissions) do
		permissions_clone[i] = v
	end
	--this is not actually required
	setmetatable(permissions_clone, { __newindex = function()end }) 

	local env 
	env = whitelist(_G, {
		'_VERSION', 'print', 'type', 'error',
		'assert', 'ipairs', 'pairs', 'next',
		'select', 'tonumber', 'tostring',
		'xpcall', 'pcall', 'unpack',
		w_perm_fn('setmetatable', permissions, 'compat_metatable', function(table, mt)
			assert((type(mt) == 'table') and (type(table) == 'table'), 'Argument not a table')
			assert(not(protected_list[table] or protected_list[mt]), 'Protected')
			return setmetatable(table, mt)
		end),
		w_perm_fn('getmetatable', permissions, 'compat_metatable', function(table)
			assert(type(table) == 'table', 'Argument not a table')
			local mt = getmetatable(table)
			assert(not(protected_list[table] or protected_list[mt]), 'Protected')
			return mt
		end),
		w_perm_fn('rawget', permissions, 'compat_metatable', rawget),
		w_perm_fn('rawset', permissions, 'compat_metatable', rawget),
		w_perm_fn('rawequal', permissions, 'compat_metatable', rawequal),
		{'coroutine', whitelist(coroutine, {
			'create', 'resume', 'running', 'status', 
			'wrap', 'yield',
		})},
		{'string', whitelist(string, {
			'byte', 'char', 'find', 'format',
			'gmatch', 'gsub', 'len', 'lower', 
			'match', 'rep', 'reverse', 'sub',
			'upper',
		})},
		{'table', whitelist(table, {
			'insert', 'maxn', 'remove', 'sort', 'concat',
			{'unpack', unpack or table.unpack},
		})},
		{'math', whitelist(math, {
			w_perm_fn('randomseed', permissions, 'compat_randomseed', math.randomseed),
			'abs', 'acos', 'asin', 'atan', 'atan2', 
			'ceil', 'cos', 'cosh', 'deg', 'exp', 
			'floor', 'fmod', 'frexp', 'huge', 'ldexp', 
			'log', 'log10', 'max', 'min', 'modf',
			'pi', 'pow', 'rad', 'random', 'sin', 
			'sinh', 'sqrt', 'tan', 'tanh',
		})},
		{'io', whitelist(io, {
			w_perm_fn('open', permissions, 'filesystem', io.open),
			'read', 'write', 'flush', 'type',
		})},
		{'os', whitelist(os, {
			w_perm_fn('exit', permissions, 'exit', os.exit),
			w_perm_fn('getenv', permissions, 'env', os.getenv),
			w_perm_fn('remove', permissions, 'filesystem', os.remove),
			w_perm_fn('rename', permissions, 'filesystem', os.rename),
			w_perm_fn('tmpname', permissions, 'filesystem', os.tmpname),
			'clock', 'date', 'difftime', 'time',
		})},
		
		--does not behave exactly like real _G.package
		{'package', {
			loaded = {},
			preload = {},
		}},

		--luajit specific

		--powder toy functions
		{'tpt', setmetatable(whitelist(tpt, {
			{'version', whitelist(tpt.version, {
				'jacob1s_mod', 'major', 'minor',
			})},
			w_perm_fn('set_pause', permissions, 'simulation_settings', tpt.set_pause),
			w_perm_fn('heat', permissions, 'simulation_settings', tpt.set_pause),
			w_perm_fn('ambient_heat', permissions, 'simulation_settings', tpt.set_pause),
			w_perm_fn('newtonian_gravity', permissions, 'simulation_settings', tpt.set_pause),
			--todo more legacy apis
		}), {
			__metatable = 0,
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
		})},
		{'fs', whitelist(fs, {
			w_cond(fs, 'list', permissions.filesystem),
			w_cond(fs, 'exists', permissions.filesystem),
			w_cond(fs, 'isFile', permissions.filesystem),
			w_cond(fs, 'isDirectory', permissions.filesystem),
			w_cond(fs, 'makeDirectory', permissions.filesystem),
			w_cond(fs, 'removeFile', permissions.filesystem),
			w_cond(fs, 'removeDirectory', permissions.filesystem),
			w_cond(fs, 'move', permissions.filesystem),
			w_cond(fs, 'copy', permissions.filesystem),
		})},
		{'graphics', whitelist(graphics, {
			'textSize', 'getColors', 'getHexColor', 
			w_cond(fs, 'drawText', permissions.graphics),
			w_cond(fs, 'drawLine', permissions.graphics),
			w_cond(fs, 'drawRect', permissions.graphics),
			w_cond(fs, 'fillRect', permissions.graphics),
			w_cond(fs, 'drawCircle', permissions.graphics),
			w_cond(fs, 'fillCircle', permissions.graphics),
		})},
		{'socket', whitelist(socket, {
			'_VERSION', '_DEBUG', 'gettime', 'sleep',
			'try', 'protect', 'newtry', 'skip',
			w_cond(socket, 'tcp', permissions.internet),
			w_cond(socket, 'udp', permissions.internet),
			w_cond(socket, 'sink', permissions.internet),
			w_cond(socket, 'select', permissions.internet),
			w_cond(socket, 'source', permissions.internet),
			--dns is missing!
		})},
		{'simulation', whitelist(simulation, {
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
			--Undocumented:
			'CELL'
		})},
		{'renderer', whitelist(renderer, {
			--permissions.render_settings
		})},
		{'event', whitelist(event, {
			
		})},
		{'bit', whitelist(bit, {
			'tobit', 'tohex', 'bnot', 'band',
			'bor', 'bxor', 'lshift', 'rshift',
			'arshift', 'rol', 'ror', 'bswap',
		})},
		{'http', whitelist(http, {
			w_cond(http, 'get', permissions.internet),
			w_cond(http, 'post', permissions.internet),
		})},
		elem = elem, --TODO!!! HACK!!! USE WHITELIST!!!,

		--Nouvelle things
		{Consts.CODE_NAME, setmetatable({
			sandboxed = true,
			permissions = permissions_clone,
			shared_of = function(mod_id)
				return Sandbox.shared_table[tostring(mod_id)] or nil
			end
		}, {
			__metatable = 0,
			__index = { shared = Sandbox.shared_table[script_id] },
			__newindex = function(self, i, v)
				if i == 'shared' then
					assert(type(v) == 'table', 'Can only share tables')
					Sandbox.shared_table[script_id] = v
				end
			end
		})}
	})

	--globals
	env._G = env
	env._ENV = env

	--aliases
	env.sim = env.simulation
	env.gfx = env.graphics
	env.ren = env.renderer
	env.evt = env.event

	--sandboxed require
	env.require = function(path)
		assert(script_dir, 'Sandboxed script tried to use `require` but has unknown script_dir')
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
			local req_lua_file_path_base = script_dir..'/'..normalized_req_path:gsub('%.', '/')

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
			ld_code = Sandbox.safeguard..ld_code
			local fn = assert(loadstring(ld_code, (chunk_name or '???require???')..':'..path))
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

	return env
end

return Env
