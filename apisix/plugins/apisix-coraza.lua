--
-- Licensed to the Apache Software Foundation (ASF) under one or more
-- contributor license agreements.  See the NOTICE file distributed with
-- this work for additional information regarding copyright ownership.
-- The ASF licenses this file to You under the Apache License, Version 2.0
-- (the "License"); you may not use this file except in compliance with
-- the License.  You may obtain a copy of the License at
--
--     http://www.apache.org/licenses/LICENSE-2.0
--
-- Unless required by applicable law or agreed to in writing, software
-- distributed under the License is distributed on an "AS IS" BASIS,
-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-- See the License for the specific language governing permissions and
-- limitations under the License.
--
local core = require("apisix.core")
local core_log = core.log
local coraza = require "resty.coraza"
local str_fmt = string.format


local schema = {
    type = "object",
    properties = {
        mode = {
            description = "waf running at block mode or monitor mode.",
            type = "string"
        },
        rules = {
            description = "self waf rules.",
            type = "array"
        },
    },
    required = {"mode"},
}

local plugin_name = "apisix-coraza"
local waf = nil

local _M = {
    version = 0.1,
    priority = 12,
    name = plugin_name,
    schema = schema,
}

function _M.check_schema(conf)
    core.log.info("check coraza schema")
    return true
end

function _M.init()
    -- call this function when plugin is loaded
    core_log.info("coraza init")
    waf = coraza.create_waf()
    local script_path = Get_script_path()
    coraza.rules_add_file(waf, str_fmt("%s../../waf_rules/crs-setup.conf.example", script_path))
    coraza.rules_add(waf, str_fmt("Include %s../../waf_rules/rules/*.conf", script_path))
end

function _M.access(conf, ctx)
    core.log.info("plugin access phase, conf: ", core.json.delay_encode(conf))
    -- each connection will be created a transaction
    coraza.do_create_transaction(_M.waf)
    coraza.do_access_filter()
    return coraza.do_handle()
end

function _M.header_filter(conf, ctx)
    core.log.info("plugin access phase, conf: ", core.json.delay_encode(conf))
    coraza.do_header_filter()
    ngx.status, _ = coraza.do_handle()
    core.response.clear_header_as_body_modified()
end

function _M.destroy()
    core.log.info("coraza destroy")
    coraza.free_waf(_M.waf)
end


function _M.log(conf, ctx)
    coraza.do_log()
    coraza.do_free_transaction()
end

function Get_script_path()
    local info = debug.getinfo(1, "S") 

    for k,v in pairs(info) do
            print(k, ":", v)
    end

    local path = info.source
    path = string.sub(path, 2, -1) -- 去掉开头的"@"
    path = string.match(path, "^.*/") -- 捕获最后一个 "/" 之前的部分 就是我们最终要的目录部分
    return path
end

return _M
