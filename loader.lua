--[[
    xrio loader — customer-facing entry point.
    This is the ONLY file you give to customers. It auths via your Cloudflare
    Worker and runs the real script in memory.

    Customer usage:
        loadstring(game:HttpGet("https://YOUR-WORKER.workers.dev/loader.lua"))()

    Setup (you):
        1. Deploy worker.js to Cloudflare Workers
        2. Replace WORKER_URL below with your Worker's URL
        3. Distribute this loader.lua via your Worker too (or via GitHub raw)
        4. Customer pastes the loadstring line into their executor
]]

local WORKER_URL = "https://xrio-vercel.vercel.app/api"  -- Vercel Functions endpoint
local KEY_FILE   = "xiro_key.txt"

local HttpService = game:GetService("HttpService")
local Players     = game:GetService("Players")
local TS          = game:GetService("TweenService")
local UIS         = game:GetService("UserInputService")

-- Reinjection guard
if _G._XRIO_LOADER_ACTIVE then
    warn("[xrio] loader 已经在运行了。重启 Roblox 客户端再注入。")
    return
end
_G._XRIO_LOADER_ACTIVE = true

if not game:IsLoaded() then game.Loaded:Wait() end

local function hwid()
    return "RBX-XRIO-LICENSE-V1-" .. tostring(Players.LocalPlayer.UserId)
end

local function urlencode(s)
    return (s:gsub("[^%w%-_.~]", function(c) return string.format("%%%02X", string.byte(c)) end))
end

-- Write a step to debug file so we can inspect what happened (Blox Strike spams console).
local _dbg_lines = {}
local function dbg(msg)
    table.insert(_dbg_lines, string.format("[%.3f] %s", tick(), tostring(msg)))
    pcall(function()
        if writefile then writefile("xrio_loader_debug.txt", table.concat(_dbg_lines, "\n")) end
    end)
end

dbg("loader_start")

-- Single-transport: HttpService:RequestAsync (in executor context).
local function fetchScript(key)
    local url = WORKER_URL .. "/loader?key=" .. urlencode(key) .. "&hwid=" .. urlencode(hwid())
    dbg("fetchScript start url=" .. url)
    local t0 = tick()
    local ok, res = pcall(function()
        return HttpService:RequestAsync({ Url = url, Method = "GET" })
    end)
    dbg(string.format("fetchScript pcall_ok=%s elapsed=%.2fs", tostring(ok), tick() - t0))
    if not ok then
        dbg("fetchScript pcall_err=" .. tostring(res):sub(1, 300))
        return nil, tostring(res):sub(1, 100)
    end
    if type(res) ~= "table" then
        return nil, "non-table response (" .. type(res) .. ")"
    end
    dbg(string.format("fetchScript StatusCode=%s BodyLen=%s", tostring(res.StatusCode), tostring(res.Body and #res.Body)))
    if res.StatusCode ~= 200 then
        local jok, parsed = pcall(HttpService.JSONDecode, HttpService, res.Body or "")
        if jok and parsed and parsed.error then return nil, parsed.error end
        return nil, "HTTP " .. tostring(res.StatusCode)
    end
    if not res.Body or #res.Body == 0 then
        return nil, "empty body (StatusCode=200)"
    end
    return res.Body, nil
end

-- ============================================================
--   Key prompt UI (matches script.lua's style)
-- ============================================================
local function showPromptAndAuth(savedKeyAttempt)
    local sg = Instance.new("ScreenGui")
    sg.Name = "XrioLoader"
    sg.ResetOnSpawn = false
    sg.IgnoreGuiInset = true
    local parented = pcall(function()
        sg.Parent = (gethui and gethui()) or game:GetService("CoreGui")
    end)
    if not parented or not sg.Parent then
        sg.Parent = Players.LocalPlayer:WaitForChild("PlayerGui")
    end

    local backdrop = Instance.new("Frame")
    backdrop.Size = UDim2.fromScale(1, 1)
    backdrop.BackgroundColor3 = Color3.new(0, 0, 0)
    backdrop.BackgroundTransparency = 1
    backdrop.BorderSizePixel = 0
    backdrop.ZIndex = 0
    backdrop.Parent = sg

    local fr = Instance.new("Frame")
    fr.Size = UDim2.new(0, 440, 0, 250)
    fr.AnchorPoint = Vector2.new(0.5, 0.5)
    fr.Position = UDim2.new(0.5, 0, 0.5, 0)
    fr.BackgroundColor3 = Color3.fromRGB(22, 22, 30)
    fr.BorderSizePixel = 0
    fr.BackgroundTransparency = 1
    fr.ZIndex = 1
    fr.Parent = sg
    local c = Instance.new("UICorner"); c.CornerRadius = UDim.new(0, 8); c.Parent = fr
    local s = Instance.new("UIStroke"); s.Color = Color3.fromRGB(0, 200, 255); s.Thickness = 1; s.Transparency = 1; s.Parent = fr

    local grad = Instance.new("UIGradient")
    grad.Color = ColorSequence.new({
        ColorSequenceKeypoint.new(0, Color3.fromRGB(34, 34, 46)),
        ColorSequenceKeypoint.new(1, Color3.fromRGB(18, 18, 26)),
    })
    grad.Rotation = 90
    grad.Parent = fr

    local scale = Instance.new("UIScale"); scale.Scale = 0.92; scale.Parent = fr

    local titleBar = Instance.new("Frame")
    titleBar.Size = UDim2.new(1, 0, 0, 44)
    titleBar.BackgroundTransparency = 1
    titleBar.Parent = fr

    local dot = Instance.new("Frame")
    dot.Size = UDim2.fromOffset(6, 6)
    dot.AnchorPoint = Vector2.new(0, 0.5)
    dot.Position = UDim2.new(0, 18, 0.5, 0)
    dot.BackgroundColor3 = Color3.fromRGB(0, 220, 255)
    dot.BorderSizePixel = 0
    dot.BackgroundTransparency = 1
    dot.Parent = titleBar
    local dotC = Instance.new("UICorner"); dotC.CornerRadius = UDim.new(1, 0); dotC.Parent = dot

    local title = Instance.new("TextLabel")
    title.Size = UDim2.new(1, -42, 1, 0)
    title.Position = UDim2.new(0, 32, 0, 0)
    title.BackgroundTransparency = 1
    title.Text = "xrio  ·  license"
    title.Font = Enum.Font.GothamBold
    title.TextSize = 15
    title.TextColor3 = Color3.fromRGB(245, 245, 250)
    title.TextTransparency = 1
    title.TextXAlignment = Enum.TextXAlignment.Left
    title.Parent = titleBar

    local accentLine = Instance.new("Frame")
    accentLine.Size = UDim2.new(1, -36, 0, 1)
    accentLine.Position = UDim2.new(0, 18, 0, 44)
    accentLine.BackgroundColor3 = Color3.fromRGB(0, 200, 255)
    accentLine.BorderSizePixel = 0
    accentLine.BackgroundTransparency = 1
    accentLine.Parent = fr

    local sub = Instance.new("TextLabel")
    sub.Size = UDim2.new(1, -36, 0, 18)
    sub.Position = UDim2.new(0, 18, 0, 56)
    sub.BackgroundTransparency = 1
    sub.Text = "Enter your key — bound to this account on first use"
    sub.Font = Enum.Font.Gotham
    sub.TextSize = 12
    sub.TextColor3 = Color3.fromRGB(150, 150, 165)
    sub.TextTransparency = 1
    sub.TextXAlignment = Enum.TextXAlignment.Left
    sub.TextWrapped = true
    sub.Parent = fr

    local box = Instance.new("TextBox")
    box.Size = UDim2.new(1, -36, 0, 40)
    box.Position = UDim2.new(0, 18, 0, 88)
    box.BackgroundColor3 = Color3.fromRGB(14, 14, 20)
    box.BackgroundTransparency = 1
    box.BorderSizePixel = 0
    box.PlaceholderText = "KEYAUTH-XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX"
    box.PlaceholderColor3 = Color3.fromRGB(95, 95, 110)
    box.Text = ""
    box.Font = Enum.Font.Code
    box.TextSize = 13
    box.TextColor3 = Color3.fromRGB(255, 255, 255)
    box.TextTransparency = 1
    box.ClearTextOnFocus = false
    box.TextXAlignment = Enum.TextXAlignment.Left
    box.Parent = fr
    local bc = Instance.new("UICorner"); bc.CornerRadius = UDim.new(0, 4); bc.Parent = box
    local bs = Instance.new("UIStroke"); bs.Color = Color3.fromRGB(60, 60, 75); bs.Thickness = 1; bs.Transparency = 1; bs.Parent = box
    local boxPad = Instance.new("UIPadding"); boxPad.PaddingLeft = UDim.new(0, 10); boxPad.PaddingRight = UDim.new(0, 10); boxPad.Parent = box

    local st = Instance.new("TextLabel")
    st.Size = UDim2.new(1, -36, 0, 32)
    st.Position = UDim2.new(0, 18, 0, 136)
    st.BackgroundTransparency = 1
    st.Text = savedKeyAttempt and "Saved key invalid — please re-enter" or ""
    st.Font = Enum.Font.Gotham
    st.TextSize = 12
    st.TextColor3 = savedKeyAttempt and Color3.fromRGB(255, 180, 100) or Color3.fromRGB(255, 120, 120)
    st.TextTransparency = 1
    st.TextXAlignment = Enum.TextXAlignment.Left
    st.TextYAlignment = Enum.TextYAlignment.Top
    st.TextWrapped = true
    st.Parent = fr

    local btn = Instance.new("TextButton")
    btn.Size = UDim2.new(1, -36, 0, 38)
    btn.Position = UDim2.new(0, 18, 1, -54)
    btn.BackgroundColor3 = Color3.fromRGB(0, 200, 255)
    btn.BackgroundTransparency = 1
    btn.BorderSizePixel = 0
    btn.AutoButtonColor = false
    btn.Text = "Verify"
    btn.Font = Enum.Font.GothamBold
    btn.TextSize = 14
    btn.TextColor3 = Color3.fromRGB(8, 12, 20)
    btn.TextTransparency = 1
    btn.Parent = fr
    local bn = Instance.new("UICorner"); bn.CornerRadius = UDim.new(0, 4); bn.Parent = btn

    local tFast = TweenInfo.new(0.18, Enum.EasingStyle.Quad, Enum.EasingDirection.Out)
    local tBack = TweenInfo.new(0.30, Enum.EasingStyle.Back, Enum.EasingDirection.Out)
    TS:Create(backdrop, tFast, {BackgroundTransparency = 0.45}):Play()
    TS:Create(scale,    tBack, {Scale = 1}):Play()
    TS:Create(fr,       tFast, {BackgroundTransparency = 0}):Play()
    TS:Create(s,        tFast, {Transparency = 0}):Play()
    TS:Create(dot,      tFast, {BackgroundTransparency = 0}):Play()
    TS:Create(accentLine, tFast, {BackgroundTransparency = 0.4}):Play()
    TS:Create(title,    tFast, {TextTransparency = 0}):Play()
    TS:Create(sub,      tFast, {TextTransparency = 0}):Play()
    TS:Create(box,      tFast, {BackgroundTransparency = 0, TextTransparency = 0}):Play()
    TS:Create(bs,       tFast, {Transparency = 0.3}):Play()
    TS:Create(btn,      tFast, {BackgroundTransparency = 0, TextTransparency = 0}):Play()
    TS:Create(st,       tFast, {TextTransparency = 0}):Play()

    box.Focused:Connect(function()
        TS:Create(bs, TweenInfo.new(0.15), {Color = Color3.fromRGB(0, 200, 255), Transparency = 0, Thickness = 1.5}):Play()
    end)
    box.FocusLost:Connect(function()
        TS:Create(bs, TweenInfo.new(0.18), {Color = Color3.fromRGB(60, 60, 75), Transparency = 0.3, Thickness = 1}):Play()
    end)

    local btnIdle  = Color3.fromRGB(0, 200, 255)
    local btnHover = Color3.fromRGB(60, 220, 255)
    local btnDown  = Color3.fromRGB(0, 170, 220)
    btn.MouseEnter:Connect(function() TS:Create(btn, TweenInfo.new(0.12), {BackgroundColor3 = btnHover}):Play() end)
    btn.MouseLeave:Connect(function() TS:Create(btn, TweenInfo.new(0.15), {BackgroundColor3 = btnIdle}):Play() end)
    btn.MouseButton1Down:Connect(function() TS:Create(btn, TweenInfo.new(0.08), {BackgroundColor3 = btnDown}):Play() end)
    btn.MouseButton1Up:Connect(function() TS:Create(btn, TweenInfo.new(0.10), {BackgroundColor3 = btnHover}):Play() end)

    -- Drag handler on title bar
    local dragStart, startPos
    titleBar.InputBegan:Connect(function(input)
        if input.UserInputType == Enum.UserInputType.MouseButton1 or input.UserInputType == Enum.UserInputType.Touch then
            dragStart = input.Position
            startPos = fr.Position
            local moveConn, endConn
            moveConn = UIS.InputChanged:Connect(function(i)
                if dragStart and (i.UserInputType == Enum.UserInputType.MouseMovement or i.UserInputType == Enum.UserInputType.Touch) then
                    local d = i.Position - dragStart
                    fr.Position = UDim2.new(
                        startPos.X.Scale, math.floor(startPos.X.Offset + d.X + 0.5),
                        startPos.Y.Scale, math.floor(startPos.Y.Offset + d.Y + 0.5)
                    )
                end
            end)
            endConn = UIS.InputEnded:Connect(function(i)
                if i.UserInputType == Enum.UserInputType.MouseButton1 or i.UserInputType == Enum.UserInputType.Touch then
                    dragStart = nil
                    if moveConn then moveConn:Disconnect() end
                    if endConn then endConn:Disconnect() end
                end
            end)
        end
    end)

    local resolved, scriptSrc
    local function attempt()
        if resolved then return end
        local key = box.Text:gsub("%s+", "")
        if #key < 5 then
            st.TextColor3 = Color3.fromRGB(255, 120, 120)
            st.Text = "Key 太短"
            return
        end
        st.TextColor3 = Color3.fromRGB(200, 200, 200)
        st.Text = "验证中..."
        btn.Active = false
        local src, err = fetchScript(key)
        btn.Active = true
        if src then
            if writefile then pcall(writefile, KEY_FILE, key) end
            scriptSrc = src
            resolved = true
            sg:Destroy()
        else
            st.TextColor3 = Color3.fromRGB(255, 120, 120)
            st.Text = "失败: " .. tostring(err)
        end
    end

    btn.MouseButton1Click:Connect(attempt)
    box.FocusLost:Connect(function(enter) if enter then attempt() end end)

    local t0 = tick()
    while not resolved do
        if tick() - t0 > 300 then break end  -- 5 min timeout
        task.wait(0.1)
    end
    if sg.Parent then sg:Destroy() end
    return scriptSrc
end

-- ============================================================
--   Main: try saved key first, then prompt
-- ============================================================
local function tryRun()
    -- Try saved key
    if isfile and isfile(KEY_FILE) then
        local rok, saved = pcall(readfile, KEY_FILE)
        if rok and type(saved) == "string" then
            saved = saved:gsub("%s+", "")
            if #saved >= 5 then
                local src, err = fetchScript(saved)
                if src then return src end
                warn("[xrio] saved key invalid: " .. tostring(err))
                -- Fall through to prompt
                return showPromptAndAuth(true)
            end
        end
    end
    return showPromptAndAuth(false)
end

local src = tryRun()
if not src then
    _G._XRIO_LOADER_ACTIVE = false
    return
end

-- Hand off to main script. The flag signals script.lua to skip its
-- internal auth do-block (loader already authed).
dbg("script src length=" .. tostring(#src) .. " first40=" .. tostring(src:sub(1, 40)))
_G._XRIO_LOADER_AUTHED = true
dbg("set _G._XRIO_LOADER_AUTHED=true; current=" .. tostring(_G._XRIO_LOADER_AUTHED))
local fn, err = loadstring(src)
if not fn then
    dbg("LOADSTRING_FAIL: " .. tostring(err))
    warn("[xrio] loadstring failed: " .. tostring(err))
    _G._XRIO_LOADER_ACTIVE = false
    _G._XRIO_LOADER_AUTHED = nil
    return
end
dbg("loadstring OK; calling pcall(fn)")
local ok, runErr = pcall(fn)
if not ok then
    dbg("PCALL_FAIL: " .. tostring(runErr):sub(1, 500))
    warn("[xrio] script runtime error: " .. tostring(runErr))
else
    dbg("script pcall returned OK")
end
_G._XRIO_LOADER_AUTHED = nil
_G._XRIO_LOADER_ACTIVE = false
