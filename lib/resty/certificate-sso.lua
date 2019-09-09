local jwt = require("resty.jwt")
local uri = require('net.url')

local _M = {}

--- Status of an authorization attempt
-- @field SUCCESS
-- @field FAIL
-- @table
local AuthStatus = {
  SUCCESS = 1,
  FAIL = 2,
}

--- Load a file from disk and return as a string
--
-- @param path 
-- @return File contents as a string
-- @raise Error if file couldn't be opened 
-- @local
local function loadFile(path)
  local fh = io.open(path, 'r')

  assert(fh, "Could not open file: " .. path)

  local content = fh:read('*all')
  fh:close()
  return content
end

--- Gets a field from a table, throwing an error if it doesn't exist
--
-- @param table
-- @param field
-- @return value in table[field]
-- @raise Error if table[field] is nil
local function requireField(table, field)
  if table[field] == nil then
    error(string.format("`%s' is a required field", field))
  end

  return table[field]
end

--- Gets the field from the table and verifies it's a PEM formated string
--
-- @param table
-- @param field
-- @return table[field]
-- @raise Error if table[field] is nil or is not a PEM-formatted string
local function requirePemField(table, field)
  local value = requireField(table, field)

  if value:find("^-----BEGIN") then
    error(string.format("Expected a PEM string in %s, got: %s\n", field, value))
  end

  return value
end

--- Gets the provided field or contents of a file specified by `#{field}_file'.
--
-- @param table
-- @param field
-- @return table[field] or contents of table[field .. "_file"]
local function requirePemFieldOrFile(table, field)
  local file_field = string.format("%s_file", field)

  if table[file_field] then
    return loadFile(table[file_field])
  else
    return requirePemField(table, field)
  end
end

--- Create a new instance of the module
--
-- @param config configuration object
-- @return instance of module
function _M.new(config)
  _config = {}

  assert(config)

  _config.cert = requirePemFieldOrFile(config, "cert")
  _config.pub_key = requirePemFieldOrFile(config, "pub_key")
  _config.private_key = requirePemFieldOrFile(config, "private_key")
  _config.sso_endpoint = requireField(config, "sso_endpoint")

  _config.ttl = config.ttl or 864000
  _config.alg = config.alg or "RS256"
  _config.payload_fields = config.payload_fields or {}

  if not _config.payload_fields.iss then
    _config.payload_fields.iss = string.format("https://%s", _config.sso_endpoint)
  end

  return setmetatable({ config = _config }, { __index = _M })
end

--- Internal helper function to format a `Cookie` header string.
--
-- @param key Name of the cookie
-- @param value Value of the cookie
-- @param audience Domain cookie will be set for
-- @param expires Expiration date, should be a unix timestamp
-- @return A formatted cookie header string
-- @local
local function formatCookie(key, value, audience, expires)
  return string.format(
    "%s=%s; Secure; HttpOnly; Path=/; Expires=%s; domain=%s", 
    key, 
    value, 
    ngx.cookie_time(expires),
    audience
  )
end

--- Given a set of claims, generate a signed JWT.
--
-- @param claims A table containing the JWT payload
-- @return A signed JWT string
-- @local
function _M.generateJwt(self, claims)
  local expires = ngx.time() + self.config.ttl
  local jwt_payload = claims
  for k, v in pairs(self.config.payload_fields) do jwt_payload[k] = v end

  ngx.log(ngx.NOTICE, string.format("Issuing a token to: %s", claims.sub))

  return jwt:sign(
    self.config.private_key,
    {
      header = {
        typ = "JWT",
        alg = self.config.alg
      },
      payload = jwt_payload
    }
  )
end

--- Checks whether a request is allowed to access the SSO endpoint.
--
-- All requests should require a client-certificate, but this function is in
-- place as an added safeguard.  Tokens will not be served unless this
-- function indicates a user is authorized.
--
-- @return A value from the AuthStatus table.
-- @local
local function authorizeRequest()
  if ngx.var.ssl_client_verify == 'SUCCESS' then
    return AuthStatus.SUCCESS
  else
    return AuthStatus.FAIL
  end
end

--- Generates a JWT payload from information in the request.
--
-- Assumes that:
--   * A query parameter `r` is present, which will be used to generate the
--     `aud` claim.
--   * A client certificate is present.  Its serial number will be used for the
--     `sub` claim.
--   * Optionally, the `email` claim is set to the email field from the 
--     subject DN in the client certificate.
--
-- @return a Table
-- @local
function _M.getRequestJwtClaims(self) 
  local audience 

  if (ngx.var.arg_r == nil) then
    ngx.header.content_type = 'text/plain'
    ngx.say("Invalid request: expecting r query arg")
    ngx.exit(ngx.HTTP_BAD_REQUEST)
  else
    audience = uri.parse(ngx.unescape_uri(ngx.var.arg_r))

    if audience == nil or audience.scheme == nil or audience.host == nil then 
      ngx.header.content_type = 'text/plain'
      ngx.say("Invalid request: could not parse r argument.")
      ngx.exit(ngx.HTTP_BAD_REQUEST)
    else
      audience = string.format("%s://%s", audience.scheme, audience.host)
    end
  end

  return {
    sub = ngx.var.ssl_client_serial,
    email = (ngx.var.ssl_client_s_dn):match('emailAddress=([^,]+)'),
    aud = audience,
    exp = ngx.time() + self.config.ttl
  }
end

--- Request handler to serve the public key for verifying JWTs.
--
-- JWTs are signed with an asymetric key.  This route serves the public key and
-- can be used by endpoints to verify a JWT.
--
-- @return nil
function _M.handleServePublicKey(self)
  ngx.header.content_type = "application/x-pem-file"
  ngx.say(self.config.pub_key)
  ngx.exit(ngx.OK)
end

--- Core request handler which guards an nginx `location` block with JWT auth.
--
-- This is the central function of the auth flow.  It should be called from an
-- `access_by_lua_block` directive.  It checks wither a JWT is present.  
-- There are two cases:
--   * The JWT is present and valid.  Here, it allows the request to pass
--     through.
--   * The JWT is either not present or is not valid.  In this case, it will
--     redirect the client to the SSO endpoint where an authenticated client
--     will be issued a new token.
--
-- @return nil
function _M.guardRequestWithAuth(self)
  -- We look for the cookie first in a cookie, then in an `Authorization` 
  -- header.
  local token;
  local authHeader = ngx.req.get_headers()['Authorization']
  local cookie = ngx.var.cookie_AccessToken

  if cookie then
    token = cookie
  elseif authHeader then
    token = authHeader:match('Bearer:[ ]*(.*)')
  end

  local jwt_verify = jwt:verify(
    self.config.cert,
    token,
    {
      lifetime_grace_period = 0,
      valid_issuers = { self.config.payload_fields.iss }
    }
  )

  if not jwt_verify['verified'] then
    local cb = string.format("https://%s/sso/callback", ngx.var.http_host)
    local redirect_to = string.format("%s://%s%s", ngx.var.scheme, ngx.var.http_host, ngx.var.request_uri)

    return ngx.redirect(string.format(
      "https://%s/auth/request?r=%s&cb=%s",
      self.config.sso_endpoint,
      ngx.escape_uri(redirect_to),
      ngx.escape_uri(cb)
    ))
  end
end

--- Handles the callback request from the SSO endpoint.
--
-- This receives the signed JWT in a query parameter, and sets it in a cookie.
-- It will then redirect to the original page that was accessed by the 
-- previously unauthenticated client.
--
-- @return nil
function _M.handleCallback(self)
  local token = ngx.var.arg_access_token
  local claims = jwt:load_jwt(token)
  local verified = jwt:verify_jwt_obj(self.config.cert, claims)

  if verified['verified'] then
    ngx.header['Set-Cookie'] = {
      formatCookie('AccessToken', token, ngx.var.http_host, claims.payload.exp)
    }
    ngx.log(ngx.NOTICE, ngx.var.arg_r)
    ngx.redirect(ngx.unescape_uri(ngx.var.arg_r))
  else
    ngx.exit(ngx.FORBIDDEN)
  end
end

--- Handle an /auth/request endpoint request
--
-- This function will check whether a user is authorized.  If they are, it will
-- generate and sign a JWT, and redirect to the callback specified in the `cb`
-- request parameter.
--
-- @return nil
function _M.handleAuthorizeRequest(self)
  if authorizeRequest() == AuthStatus.SUCCESS then
    local claims = self:getRequestJwtClaims()
    local jwt = self:generateJwt(claims)

    -- Extract redirect URL, and append access token to args
    local url = uri.parse(ngx.unescape_uri(ngx.var.arg_cb))
    url.query.access_token = jwt
    url.query.r = ngx.unescape_uri(ngx.var.arg_r)

    return ngx.redirect(tostring(url:normalize()))
  else
    ngx.exit(ngx.HTTP_UNAUTHORIZED)
  end
end

--- Handle an /auth/token endpoint request
--
-- Check whether the user is authorized.  If they are, generate and sign a JWT
-- and serve it directly in the response body.
--
-- @return nil
function _M.handleGetToken(self)
  if authorizeRequest() == AuthStatus.SUCCESS then
    local token = self:generateJwt(self:getRequestJwtClaims())

    ngx.header.content_type = 'application/json'
    ngx.say(string.format('{"access_token":"%s"}', token))
    ngx.exit(ngx.OK)
  else
    ngx.exit(ngx.HTTP_UNAUTHORIZED)
  end
end

return _M
