--[[
    xrio loader v2 — pure GitHub architecture (no cloud function dependency)
    Validates customer key against keys.json, decrypts encrypted script, runs in memory.

    Architecture:
      1. Loader fetches keys.json from public GitHub (HttpGet works)
      2. Customer enters license key
      3. Loader checks if (key, userid) tuple exists in keys.json
      4. If valid, fetches script.enc, decrypts with MASTER_KEY, runs

    To add a customer:
      Edit keys.json in xrio-loader repo, add entry: {"key":"NEW_KEY","userid":12345}

    To revoke: remove entry from keys.json (takes effect on next inject).
]]

if _G._XRIO_LOADER_ACTIVE then
    warn("[xrio] loader 已经在跑了。如需重载: _G._XRIO_LOADER_ACTIVE = nil")
    return
end
_G._XRIO_LOADER_ACTIVE = true

local KEYS_URL   = "https://raw.githubusercontent.com/67bacon/xrio-loader/main/keys.json"
local SCRIPT_URL = "https://raw.githubusercontent.com/67bacon/xrio-loader/main/script.enc"
local MASTER_KEY = "26491ba69f965e7dc2a6dfb0b91c9eb6ed22f7459dce9fd5f8045c7775aaef0d"
local KEY_FILE   = "xiro_key.txt"

local HttpService = game:GetService("HttpService")
local Players     = game:GetService("Players")
local TS          = game:GetService("TweenService")
local UIS         = game:GetService("UserInputService")

if not game:IsLoaded() then game.Loaded:Wait() end

-- =====================================================================
-- SHA256 (pure Lua, compact). Used to derive decryption keystream.
-- =====================================================================
local SHA256 do
    local bit = bit32 or bit
    local band, bor, bxor, bnot = bit.band, bit.bor, bit.bxor, bit.bnot
    local lshift, rshift = bit.lshift, bit.rshift
    local function rrotate(x, n) return bor(rshift(x, n), lshift(x, 32 - n)) % 0x100000000 end

    local K = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    }

    local function preprocess(msg)
        local ml = #msg * 8
        msg = msg .. "\128"
        while (#msg % 64) ~= 56 do msg = msg .. "\0" end
        for i = 7, 0, -1 do
            msg = msg .. string.char(band(rshift(ml, i * 8), 0xff))
        end
        return msg
    end

    function SHA256(msg)
        local h = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19}
        msg = preprocess(msg)
        for ch = 1, #msg, 64 do
            local w = {}
            for i = 0, 15 do
                local p = ch + i * 4
                w[i+1] = bor(lshift(msg:byte(p), 24), lshift(msg:byte(p+1), 16), lshift(msg:byte(p+2), 8), msg:byte(p+3))
            end
            for i = 17, 64 do
                local s0 = bxor(rrotate(w[i-15], 7), rrotate(w[i-15], 18), rshift(w[i-15], 3))
                local s1 = bxor(rrotate(w[i-2], 17), rrotate(w[i-2], 19), rshift(w[i-2], 10))
                w[i] = (w[i-16] + s0 + w[i-7] + s1) % 0x100000000
            end
            local a, b, c, d, e, f, g, hh = h[1], h[2], h[3], h[4], h[5], h[6], h[7], h[8]
            for i = 1, 64 do
                local S1 = bxor(rrotate(e, 6), rrotate(e, 11), rrotate(e, 25))
                local ch_ = bxor(band(e, f), band(bnot(e), g))
                local t1 = (hh + S1 + ch_ + K[i] + w[i]) % 0x100000000
                local S0 = bxor(rrotate(a, 2), rrotate(a, 13), rrotate(a, 22))
                local mj = bxor(band(a, b), band(a, c), band(b, c))
                local t2 = (S0 + mj) % 0x100000000
                hh = g; g = f; f = e; e = (d + t1) % 0x100000000
                d = c; c = b; b = a; a = (t1 + t2) % 0x100000000
            end
            h[1] = (h[1] + a) % 0x100000000; h[2] = (h[2] + b) % 0x100000000
            h[3] = (h[3] + c) % 0x100000000; h[4] = (h[4] + d) % 0x100000000
            h[5] = (h[5] + e) % 0x100000000; h[6] = (h[6] + f) % 0x100000000
            h[7] = (h[7] + g) % 0x100000000; h[8] = (h[8] + hh) % 0x100000000
        end
        local out = {}
        for i = 1, 8 do
            local v = h[i]
            out[#out+1] = string.char(band(rshift(v, 24), 0xff), band(rshift(v, 16), 0xff), band(rshift(v, 8), 0xff), band(v, 0xff))
        end
        return table.concat(out)
    end
end

-- =====================================================================
-- Base64 decode
-- =====================================================================
local function b64decode(s)
    local alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    local map = {}
    for i = 1, #alphabet do map[alphabet:sub(i, i):byte()] = i - 1 end
    s = s:gsub("[^%w%+%/%=]", "")
    local out, i = {}, 1
    while i <= #s do
        local b1 = map[s:byte(i)]; local b2 = map[s:byte(i+1)]
        local c3 = s:byte(i+2); local c4 = s:byte(i+3)
        if not b1 or not b2 then break end
        local n = b1 * 4 + math.floor(b2 / 16)
        out[#out+1] = string.char(n)
        if c3 and c3 ~= 61 then
            local b3 = map[c3]
            out[#out+1] = string.char((b2 % 16) * 16 + math.floor(b3 / 4))
            if c4 and c4 ~= 61 then
                local b4 = map[c4]
                out[#out+1] = string.char((b3 % 4) * 64 + b4)
            end
        end
        i = i + 4
    end
    return table.concat(out)
end

-- =====================================================================
-- Hex to bytes
-- =====================================================================
local function hex2bin(hex)
    local out = {}
    for i = 1, #hex, 2 do out[#out+1] = string.char(tonumber(hex:sub(i, i+1), 16)) end
    return table.concat(out)
end

-- =====================================================================
-- Decrypt: XOR ciphertext with keystream derived from SHA256(seed || counter)
-- =====================================================================
local function decrypt(ciphertext, master_key_hex)
    local seed = hex2bin(master_key_hex)
    local out = {}
    local pos = 1
    local counter = 0
    local bit = bit32 or bit
    while pos <= #ciphertext do
        local counter_bytes = string.char(0, 0, 0, 0, 0, 0, 0, 0)
        do
            local n = counter
            local buf = {}
            for i = 0, 7 do buf[8-i] = n % 256; n = math.floor(n / 256) end
            counter_bytes = string.char(buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7], buf[8])
        end
        local block = SHA256(seed .. counter_bytes)
        for i = 1, 32 do
            if pos > #ciphertext then break end
            out[pos] = string.char(bit.bxor(ciphertext:byte(pos), block:byte(i)))
            pos = pos + 1
        end
        counter = counter + 1
    end
    return table.concat(out)
end

-- =====================================================================
-- Auth check: customer key must match (key, userid) in keys.json.
-- =====================================================================
local function checkKey(enteredKey)
    local ok, body = pcall(function() return game:HttpGet(KEYS_URL) end)
    if not ok or not body or #body == 0 then return false, "无法获取 keys.json" end
    local jok, list = pcall(HttpService.JSONDecode, HttpService, body)
    if not jok or type(list) ~= "table" then return false, "keys.json 格式错误" end
    local myId = Players.LocalPlayer.UserId
    for _, entry in ipairs(list) do
        if entry.key == enteredKey and tonumber(entry.userid) == myId then
            return true
        end
    end
    return false, "卡密无效或未绑定此账号"
end

-- =====================================================================
-- Fetch encrypted script + decrypt
-- =====================================================================
local function fetchAndDecrypt()
    local ok, enc = pcall(function() return game:HttpGet(SCRIPT_URL) end)
    if not ok or not enc or #enc == 0 then return nil, "无法下载脚本" end
    local cipher = b64decode(enc)
    local plain = decrypt(cipher, MASTER_KEY)
    return plain, nil
end

-- =====================================================================
-- License UI
-- =====================================================================
local function showPromptAndAuth(savedKeyInvalid)
    local sg = Instance.new("ScreenGui")
    sg.Name = "XrioLoader"
    sg.ResetOnSpawn = false
    sg.IgnoreGuiInset = true
    pcall(function() sg.Parent = (gethui and gethui()) or game:GetService("CoreGui") end)
    if not sg.Parent then sg.Parent = Players.LocalPlayer:WaitForChild("PlayerGui") end

    local W, H = 480, 290

    -- Soft drop shadow (layered frames, no asset image)
    for i = 1, 8 do
        local sh = Instance.new("Frame")
        sh.AnchorPoint = Vector2.new(0.5, 0.5)
        sh.Size = UDim2.fromOffset(W + i * 5, H + i * 5)
        sh.Position = UDim2.new(0.5, 0, 0.5, i + 2)
        sh.BackgroundColor3 = Color3.fromRGB(0, 0, 0)
        sh.BackgroundTransparency = 0.84 + i * 0.018
        sh.BorderSizePixel = 0
        sh.ZIndex = 0
        local shc = Instance.new("UICorner"); shc.CornerRadius = UDim.new(0, 14); shc.Parent = sh
        sh.Parent = sg
    end

    -- CanvasGroup wrapper for smooth group transparency animations
    local cg = Instance.new("CanvasGroup")
    cg.Size = UDim2.fromOffset(W, H)
    cg.Position = UDim2.new(0.5, -W/2, 0.5, -H/2)
    cg.BackgroundTransparency = 1
    cg.GroupTransparency = 0
    cg.ZIndex = 1
    cg.Parent = sg

    local fr = Instance.new("Frame")
    fr.Size = UDim2.fromScale(1, 1)
    fr.BackgroundColor3 = Color3.fromRGB(13, 13, 19)
    fr.BorderSizePixel = 0
    fr.Parent = cg

    local fc = Instance.new("UICorner"); fc.CornerRadius = UDim.new(0, 12); fc.Parent = fr
    local fs = Instance.new("UIStroke"); fs.Color = Color3.fromRGB(70, 70, 88); fs.Transparency = 0.4; fs.Thickness = 1; fs.Parent = fr

    -- Subtle vertical gradient on body
    local frGrad = Instance.new("UIGradient")
    frGrad.Color = ColorSequence.new({
        ColorSequenceKeypoint.new(0, Color3.fromRGB(26, 26, 36)),
        ColorSequenceKeypoint.new(0.5, Color3.fromRGB(16, 16, 23)),
        ColorSequenceKeypoint.new(1, Color3.fromRGB(11, 11, 16)),
    })
    frGrad.Rotation = 90
    frGrad.Parent = fr

    -- Decorative accent stripe on top edge (cyan glow)
    local topAccent = Instance.new("Frame")
    topAccent.Size = UDim2.new(1, -120, 0, 2)
    topAccent.Position = UDim2.new(0, 60, 0, 0)
    topAccent.BackgroundColor3 = Color3.fromRGB(0, 200, 255)
    topAccent.BorderSizePixel = 0
    topAccent.Parent = fr
    local accGrad = Instance.new("UIGradient")
    accGrad.Transparency = NumberSequence.new({
        NumberSequenceKeypoint.new(0, 1),
        NumberSequenceKeypoint.new(0.5, 0.2),
        NumberSequenceKeypoint.new(1, 1),
    })
    accGrad.Parent = topAccent

    local titleBar = Instance.new("Frame")
    titleBar.Size = UDim2.new(1, 0, 0, 50)
    titleBar.BackgroundTransparency = 1
    titleBar.Parent = fr

    -- Divider line under title bar
    local divider = Instance.new("Frame")
    divider.Size = UDim2.new(1, -40, 0, 1)
    divider.Position = UDim2.fromOffset(20, 50)
    divider.BackgroundColor3 = Color3.fromRGB(50, 50, 65)
    divider.BorderSizePixel = 0
    divider.Parent = fr
    local divGrad = Instance.new("UIGradient")
    divGrad.Transparency = NumberSequence.new({
        NumberSequenceKeypoint.new(0, 1),
        NumberSequenceKeypoint.new(0.5, 0),
        NumberSequenceKeypoint.new(1, 1),
    })
    divGrad.Parent = divider

    local dot = Instance.new("Frame")
    dot.Size = UDim2.fromOffset(7, 7)
    dot.Position = UDim2.new(0, 22, 0.5, -3.5)
    dot.BackgroundColor3 = Color3.fromRGB(0, 200, 255)
    dot.BorderSizePixel = 0
    local dc = Instance.new("UICorner"); dc.CornerRadius = UDim.new(1, 0); dc.Parent = dot
    dot.Parent = titleBar

    -- Dot glow (slightly larger transparent ring behind the dot)
    local dotGlow = Instance.new("Frame")
    dotGlow.Size = UDim2.fromOffset(13, 13)
    dotGlow.Position = UDim2.new(0, 19, 0.5, -6.5)
    dotGlow.BackgroundColor3 = Color3.fromRGB(0, 200, 255)
    dotGlow.BackgroundTransparency = 0.7
    dotGlow.BorderSizePixel = 0
    local dgc = Instance.new("UICorner"); dgc.CornerRadius = UDim.new(1, 0); dgc.Parent = dotGlow
    dotGlow.Parent = titleBar

    -- Animate the dot + glow — soft breathing pulse
    task.spawn(function()
        while dot.Parent do
            TS:Create(dot,     TweenInfo.new(1.2, Enum.EasingStyle.Sine, Enum.EasingDirection.InOut), {BackgroundTransparency = 0.5}):Play()
            TS:Create(dotGlow, TweenInfo.new(1.2, Enum.EasingStyle.Sine, Enum.EasingDirection.InOut), {BackgroundTransparency = 0.92}):Play()
            task.wait(1.2)
            if not dot.Parent then break end
            TS:Create(dot,     TweenInfo.new(1.2, Enum.EasingStyle.Sine, Enum.EasingDirection.InOut), {BackgroundTransparency = 0}):Play()
            TS:Create(dotGlow, TweenInfo.new(1.2, Enum.EasingStyle.Sine, Enum.EasingDirection.InOut), {BackgroundTransparency = 0.7}):Play()
            task.wait(1.2)
        end
    end)

    local title = Instance.new("TextLabel")
    title.Size = UDim2.fromOffset(120, 18)
    title.Position = UDim2.fromOffset(38, 12)
    title.BackgroundTransparency = 1
    title.Text = "xrio"
    title.Font = Enum.Font.GothamBold
    title.TextSize = 16
    title.TextXAlignment = Enum.TextXAlignment.Left
    title.TextColor3 = Color3.fromRGB(235, 235, 240)
    title.Parent = titleBar

    local subtitle = Instance.new("TextLabel")
    subtitle.Size = UDim2.fromOffset(140, 12)
    subtitle.Position = UDim2.fromOffset(38, 30)
    subtitle.BackgroundTransparency = 1
    subtitle.Text = "LICENSE / SECURE AUTH"
    subtitle.Font = Enum.Font.Gotham
    subtitle.TextSize = 9
    subtitle.TextXAlignment = Enum.TextXAlignment.Left
    subtitle.TextColor3 = Color3.fromRGB(110, 110, 125)
    subtitle.Parent = titleBar

    -- UserId display (right side of title bar)
    local uidLabel = Instance.new("TextLabel")
    uidLabel.Size = UDim2.fromOffset(220, 14)
    uidLabel.Position = UDim2.new(1, -240, 0, 12)
    uidLabel.BackgroundTransparency = 1
    uidLabel.Text = "USERID  ·  " .. tostring(Players.LocalPlayer.UserId)
    uidLabel.Font = Enum.Font.Code
    uidLabel.TextSize = 11
    uidLabel.TextXAlignment = Enum.TextXAlignment.Right
    uidLabel.TextColor3 = Color3.fromRGB(140, 140, 155)
    uidLabel.Parent = titleBar

    local uidHint = Instance.new("TextLabel")
    uidHint.Size = UDim2.fromOffset(220, 11)
    uidHint.Position = UDim2.new(1, -240, 0, 30)
    uidHint.BackgroundTransparency = 1
    uidHint.Text = "share with seller to receive a key"
    uidHint.Font = Enum.Font.Gotham
    uidHint.TextSize = 9
    uidHint.TextXAlignment = Enum.TextXAlignment.Right
    uidHint.TextColor3 = Color3.fromRGB(85, 85, 95)
    uidHint.Parent = titleBar

    local prompt = Instance.new("TextLabel")
    prompt.Size = UDim2.new(1, -50, 0, 18)
    prompt.Position = UDim2.fromOffset(25, 66)
    prompt.BackgroundTransparency = 1
    prompt.Text = "Enter license key"
    prompt.Font = Enum.Font.GothamMedium
    prompt.TextSize = 13
    prompt.TextXAlignment = Enum.TextXAlignment.Left
    prompt.TextColor3 = Color3.fromRGB(200, 200, 210)
    prompt.Parent = fr

    local promptSub = Instance.new("TextLabel")
    promptSub.Size = UDim2.new(1, -50, 0, 14)
    promptSub.Position = UDim2.fromOffset(25, 86)
    promptSub.BackgroundTransparency = 1
    promptSub.Text = "Bound to your Roblox account on first use"
    promptSub.Font = Enum.Font.Gotham
    promptSub.TextSize = 11
    promptSub.TextXAlignment = Enum.TextXAlignment.Left
    promptSub.TextColor3 = Color3.fromRGB(110, 110, 125)
    promptSub.Parent = fr

    local box = Instance.new("TextBox")
    box.Size = UDim2.new(1, -50, 0, 42)
    box.Position = UDim2.fromOffset(25, 112)
    box.BackgroundColor3 = Color3.fromRGB(20, 20, 28)
    box.BorderSizePixel = 0
    box.PlaceholderText = "xrio-XXXXXX-XXXXXX-XXXXXX-XXXXXX"
    box.PlaceholderColor3 = Color3.fromRGB(65, 65, 80)
    box.Text = ""
    box.Font = Enum.Font.Code
    box.TextSize = 13
    box.TextColor3 = Color3.fromRGB(225, 225, 235)
    box.ClearTextOnFocus = false
    box.TextXAlignment = Enum.TextXAlignment.Center
    local bc = Instance.new("UICorner"); bc.CornerRadius = UDim.new(0, 8); bc.Parent = box
    local bs = Instance.new("UIStroke"); bs.Color = Color3.fromRGB(55, 55, 70); bs.Transparency = 0.3; bs.Thickness = 1; bs.Parent = box
    box.Parent = fr

    -- Left accent on input box
    local boxAccent = Instance.new("Frame")
    boxAccent.Size = UDim2.fromOffset(3, 28)
    boxAccent.Position = UDim2.new(0, 25, 0, 119)
    boxAccent.BackgroundColor3 = Color3.fromRGB(0, 200, 255)
    boxAccent.BackgroundTransparency = 0.4
    boxAccent.BorderSizePixel = 0
    local bac = Instance.new("UICorner"); bac.CornerRadius = UDim.new(1, 0); bac.Parent = boxAccent
    boxAccent.Parent = fr

    local st = Instance.new("TextLabel")
    st.Size = UDim2.new(1, -50, 0, 14)
    st.Position = UDim2.fromOffset(25, 162)
    st.BackgroundTransparency = 1
    st.Text = savedKeyInvalid and "Saved key invalid — please re-enter" or ""
    st.Font = Enum.Font.Gotham
    st.TextSize = 11
    st.TextXAlignment = Enum.TextXAlignment.Left
    st.TextColor3 = Color3.fromRGB(255, 110, 110)
    st.Parent = fr

    local btn = Instance.new("TextButton")
    btn.Size = UDim2.new(1, -50, 0, 44)
    btn.Position = UDim2.new(0, 25, 1, -64)
    btn.BackgroundColor3 = Color3.fromRGB(0, 200, 255)
    btn.BorderSizePixel = 0
    btn.Text = "Verify"
    btn.Font = Enum.Font.GothamBold
    btn.TextSize = 14
    btn.TextColor3 = Color3.fromRGB(15, 15, 22)
    btn.AutoButtonColor = false
    local bnc = Instance.new("UICorner"); bnc.CornerRadius = UDim.new(0, 6); bnc.Parent = btn
    -- Vertical gradient on button (lighter top, darker bottom — gives depth)
    local btnGrad = Instance.new("UIGradient")
    btnGrad.Color = ColorSequence.new({
        ColorSequenceKeypoint.new(0, Color3.fromRGB(80, 220, 255)),
        ColorSequenceKeypoint.new(1, Color3.fromRGB(0, 180, 235)),
    })
    btnGrad.Rotation = 90
    btnGrad.Parent = btn

    -- Button inner stroke for depth
    local btnStroke = Instance.new("UIStroke")
    btnStroke.Color = Color3.fromRGB(120, 230, 255)
    btnStroke.Transparency = 0.5
    btnStroke.Thickness = 1
    btnStroke.ApplyStrokeMode = Enum.ApplyStrokeMode.Border
    btnStroke.Parent = btn

    btn.Parent = fr

    -- Footer / status bar at bottom
    local footer = Instance.new("Frame")
    footer.Size = UDim2.new(1, 0, 0, 18)
    footer.Position = UDim2.new(0, 0, 1, -18)
    footer.BackgroundTransparency = 1
    footer.Parent = fr

    local footerL = Instance.new("TextLabel")
    footerL.Size = UDim2.new(0.5, -10, 1, 0)
    footerL.Position = UDim2.fromOffset(25, 0)
    footerL.BackgroundTransparency = 1
    footerL.Text = "● secure"
    footerL.Font = Enum.Font.Gotham
    footerL.TextSize = 9
    footerL.TextXAlignment = Enum.TextXAlignment.Left
    footerL.TextColor3 = Color3.fromRGB(80, 200, 130)
    footerL.Parent = footer

    local footerR = Instance.new("TextLabel")
    footerR.Size = UDim2.new(0.5, -10, 1, 0)
    footerR.Position = UDim2.new(0.5, 0, 0, 0)
    footerR.BackgroundTransparency = 1
    footerR.Text = "v2.0"
    footerR.Font = Enum.Font.Code
    footerR.TextSize = 9
    footerR.TextXAlignment = Enum.TextXAlignment.Right
    footerR.TextColor3 = Color3.fromRGB(85, 85, 100)
    footerR.Parent = footer

    local resolved, scriptSrc
    local function attempt()
        if resolved then return end
        local key = box.Text:gsub("%s+", "")
        if #key < 5 then
            st.TextColor3 = Color3.fromRGB(255, 120, 120); st.Text = "Key 太短"; return
        end
        st.TextColor3 = Color3.fromRGB(200, 200, 200); st.Text = "验证中..."
        btn.Active = false
        local valid, err = checkKey(key)
        if not valid then
            st.TextColor3 = Color3.fromRGB(255, 120, 120); st.Text = "失败: " .. tostring(err)
            btn.Active = true; return
        end
        st.TextColor3 = Color3.fromRGB(200, 200, 200); st.Text = "解密脚本..."
        local src, derr = fetchAndDecrypt()
        btn.Active = true
        if not src then
            st.TextColor3 = Color3.fromRGB(255, 120, 120); st.Text = "失败: " .. tostring(derr)
            return
        end
        if writefile then pcall(writefile, KEY_FILE, key) end
        scriptSrc = src
        resolved = true
        sg:Destroy()
    end

    btn.MouseButton1Click:Connect(attempt)
    box.FocusLost:Connect(function(enter) if enter then attempt() end end)

    -- Focus glow: cyan stroke when typing
    box.Focused:Connect(function() TS:Create(bs, TweenInfo.new(0.18), {Color = Color3.fromRGB(0, 200, 255), Transparency = 0, Thickness = 1.5}):Play() end)
    box.FocusLost:Connect(function() TS:Create(bs, TweenInfo.new(0.20), {Color = Color3.fromRGB(60, 60, 75), Transparency = 0.3, Thickness = 1}):Play() end)

    -- Button hover/press feedback (color only, avoids size-induced subpixel shake)
    btn.MouseEnter:Connect(function() TS:Create(btnGrad, TweenInfo.new(0.12), {Color = ColorSequence.new({
        ColorSequenceKeypoint.new(0, Color3.fromRGB(110, 235, 255)),
        ColorSequenceKeypoint.new(1, Color3.fromRGB(20, 200, 255)),
    })}):Play() end)
    btn.MouseLeave:Connect(function() TS:Create(btnGrad, TweenInfo.new(0.15), {Color = ColorSequence.new({
        ColorSequenceKeypoint.new(0, Color3.fromRGB(80, 220, 255)),
        ColorSequenceKeypoint.new(1, Color3.fromRGB(0, 180, 235)),
    })}):Play() end)

    -- Drag the panel via title bar
    do
        local dragStart, startPos
        titleBar.InputBegan:Connect(function(input)
            if input.UserInputType == Enum.UserInputType.MouseButton1 or input.UserInputType == Enum.UserInputType.Touch then
                dragStart = input.Position
                startPos = cg.Position
                local moveConn, endConn
                moveConn = UIS.InputChanged:Connect(function(i)
                    if dragStart and (i.UserInputType == Enum.UserInputType.MouseMovement or i.UserInputType == Enum.UserInputType.Touch) then
                        local d = i.Position - dragStart
                        cg.Position = UDim2.new(
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
    end

    -- Fade-in entrance via CanvasGroup GroupTransparency (smooth, no flicker)
    cg.GroupTransparency = 1
    cg.Size = UDim2.fromOffset(math.floor(W * 0.96), math.floor(H * 0.96))
    cg.Position = UDim2.new(0.5, math.floor(-W * 0.96 / 2), 0.5, math.floor(-H * 0.96 / 2))
    TS:Create(cg, TweenInfo.new(0.32, Enum.EasingStyle.Quart, Enum.EasingDirection.Out), {
        GroupTransparency = 0,
        Size = UDim2.fromOffset(W, H),
        Position = UDim2.new(0.5, -W/2, 0.5, -H/2),
    }):Play()

    local t0 = tick()
    while not resolved do
        if tick() - t0 > 300 then break end
        task.wait(0.1)
    end
    if sg.Parent then sg:Destroy() end
    return scriptSrc
end

-- =====================================================================
-- Main flow
-- =====================================================================
local function tryRun()
    if isfile and isfile(KEY_FILE) then
        local rok, saved = pcall(readfile, KEY_FILE)
        if rok and type(saved) == "string" then
            saved = saved:gsub("%s+", "")
            if #saved >= 5 then
                local valid = checkKey(saved)
                if valid then
                    local src = fetchAndDecrypt()
                    if src then return src end
                end
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

_G._XRIO_LOADER_AUTHED = true
local fn, err = loadstring(src)
if not fn then
    warn("[xrio] loadstring failed: " .. tostring(err))
    _G._XRIO_LOADER_ACTIVE = false
    _G._XRIO_LOADER_AUTHED = nil
    return
end
local ok, runErr = pcall(fn)
if not ok then warn("[xrio] script runtime error: " .. tostring(runErr)) end
_G._XRIO_LOADER_AUTHED = nil
_G._XRIO_LOADER_ACTIVE = false
