local M = {}

M.sandbox_helper_loaded = false

M.sandbox = function(code, is_compat_mode, permissions)
	local fn,err = loadstring(code)
	if not fn then return false,err end

	if not permissions.escape_sandbox then
		if not M.sandbox_helper_loaded then
			print('Sandbox helper is not loaded, metatable permissions are unsafe witout it and therefore will be disabled!')
			permissions.metatable = false
		end

		local permissions_clone = {}
		for i,v in pairs(permissions) do
			permissions_clone[i] = v
		end
		setmetatable(permissions_clone, { __newindex = function()end }) --this is not required
		
		--fixme: this can probably load bytecode
		local env = {
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
			unpack = unpack,
			_VERSION = _VERSION,
			xpcall = xpcall,
			coroutine = {
				create = coroutine.create, --todo point to our metatable
				resume = coroutine.resume,
				running = coroutine.running,
				status = coroutine.status,
				wrap = coroutine.wrap,
				yield = coroutine.yield,
			},
			string = {
				--todo: should string.dump be allowed?
				--todo somehow point all strings here???
				byte = string.byte,
				char = string.char,
				find = string.find,
				format = string.format,
				gmatch = string.gmatch,
				gsub = string.gsub,
				len = string.len,
				lower = string.lower,
				match = string.match,
				rep = string.rep,
				reverse = string.reverse,
				sub = string.sub,
				upper = string.upper,
			},
			table = {
				insert = table.insert,
				maxn = table.maxn,
				remove = table.remove,
				sort = table.sort,
			},
			math = {
				abs = math.abs,
				acos = math.acos,
				asin = math.asin,
				atan = math.atan,
				atan2 = math.atan2,
				ceil = math.ceil,
				cos = math.cos,
				cosh = math.cosh,
				deg = math.deg,
				exp = math.exp,
				floor = math.floor,
				fmod = math.fmod,
				frexp = math.frexp,
				huge = math.huge,
				ldexp = math.ldexp,
				log = math.log,
				log10 = math.log10,
				max = math.max,
				min = math.min,
				modf = math.modf,
				pi = math.pi,
				pow = math.pow,
				rad = math.rad,
				--todo implement our own little pseudo-rng
				--use it to whitelist randomseed!
				random = math.random,
				sin = math.sin,
				sinh = math.sinh,
				sqrt = math.sqrt,
				tan = math.tan,
				tanh = math.tanh,
			},
			io = {
				open = permissions.filesystem and os.open or nil,
				read = io.read,
				write = io.write,
				flush = io.flush,
				type = io.type,
			},
			os = {
				clock = os.clock,
				date = os.date, --this can crash on some systems
				exit = permissions.exit and os.exit or nil,
				getenv = permissions.env and os.env or nil,
				difftime = os.difftime,
				--execute = permissions.execute and os.execute or nil,
				remove = permissions.filesystem and os.remove or nil,
				rename = permissions.filesystem and os.rename or nil,
				time = os.time,
				tmpname = permissions.filesystem and os.tmpname or nil,
			},
			setmetatable = permissions.metatable and setmetatable,
			getmetatable = permissions.metatable and getmetatable,
			
			
			--luajit specific
			--ffi = permissions.execute and ffi or nil,
			--jit = permissions.control_jit and jit or nil,

			--powder toy functions
			fs = {
				list = permissions.filesystem and fs.list or nil,
				exists = permissions.filesystem and fs.exists or nil,
				isFile = permissions.filesystem and fs.isFile or nil,
				isDirectory = permissions.filesystem and fs.isDirectory or nil,
				makeDirectory = permissions.filesystem and fs.makeDirectory or nil,
				removeFile = permissions.filesystem and fs.removeFile or nil,
				removeDirectory = permissions.filesystem and fs.removeDirectory or nil,
				removeFile = permissions.filesystem and fs.removeFile or nil,
				move = permissions.filesystem and fs.move or nil,
				copy = permissions.filesystem and fs.copy or nil,
			},
			graphics = {
				textSize = graphics.textSize,
				drawText = permissions.graphics and graphics.drawText or nil,
				drawLine = permissions.graphics and graphics.drawLine or nil,
				drawRect = permissions.graphics and graphics.drawRect or nil,
				fillRect = permissions.graphics and graphics.fillRect or nil,
				drawCircle = permissions.graphics and graphics.drawCircle or nil,
				fillCircle = permissions.graphics and graphics.fillCircle or nil,
				getColors = graphics.getColors,
				getHexColor = graphics.getHexColor,
			},
	
		}
		--todo sandboxed events, sould stop after the script is disabled
		--todo implement sandboxed require, loadstring etc
		--todo scoped filesystem and safe scoped requires!
		env._G = env
		env._ENV = env
		env[consts.CODE_NAME] = {
			sandboxed = true,
			permissions = permissions_clone,
		}

		fn = setfenv(fn, env)
	end

	local obj = {
		fn = fn,
		__call = function(self) return pcall(self.fn) end
	}
	return setmetatable(obj, obj)
end

M.load_sandbox_helper = function()
	M.sandbox_helper_loaded = assert(not M.sandbox_helper_loaded, 'sandbox helper already loaded')
	local shared_lock = ""
	getmetatable("").__metatable = ""
	--getmetatable(coroutine.create(function()end)).__metatable = ""
end

return M
