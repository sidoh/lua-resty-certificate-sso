local jwt = require("resty.jwt")
local uri = require('net.url')
local validators = require("resty.jwt-validators")
local random = require "resty.random"
local str = require "resty.string"
local authorizer = require "resty.sso-authorizer"

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
local function load_file(path)
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
-- @param default return this if field is not set
-- @return value in table[field]
-- @raise Error if table[field] is nil
local function require_field(table, field, default)
  if table[field] == nil then
    if default == nil then
      error(string.format("`%s' is a required field", field))
    else
      return default
    end
  end

  return table[field]
end

--- Gets the field from the table and verifies it's a PEM formated string
--
-- @param table
-- @param field
-- @return table[field]
-- @raise Error if table[field] is nil or is not a PEM-formatted string
local function require_pem_field(table, field)
  local value = require_field(table, field)

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
local function require_pem_field_or_file(table, field)
  local file_field = string.format("%s_file", field)

  if table[file_field] then
    return load_file(table[file_field])
  else
    return require_pem_field(table, field)
  end
end

--- Create a new instance of the module
--
-- @param config configuration object
-- @return instance of module
function _M.new(config)
  local _config = {}

  assert(config)

  local permissions = config.permissions or {}
  local default_permissions = config.default_permissions or {"*"}

  _config.pub_key = require_pem_field_or_file(config, "pub_key")
  _config.private_key = require_pem_field_or_file(config, "private_key")
  _config.sso_endpoint = require_field(config, "sso_endpoint")
  _config.audience_domain = require_field(config, "audience_domain")
  _config.domain_pattern = string.format("^[a-zA-Z0-9.-]*.?%s$", _config.audience_domain)

  _config.ttl = config.ttl or 864000
  _config.alg = config.alg or "RS256"
  _config.auth_code_ttl = config.auth_code_ttl or 1
  _config.auth_code_length = config.auth_code_length or 32
  _config.payload_fields = config.payload_fields or {}
  _config.expiry_serial = config.expiry_serial or 1
  _config.callback_endpoint = config.callback_endpoint or "/auth/callback"
  _config.authorize_endpoint = config.authorize_endpoint or "/auth/authorize"
  _config.cookie_name = config.cookie_name or "AccessToken"
  _config.allow_custom_expiry = require_field(config, "allow_custom_expiry", true)

  if not _config.payload_fields.iss then
    _config.payload_fields.iss = string.format("https://%s", _config.sso_endpoint)
  end

  return setmetatable({
    config = _config,
    tokens_by_auth_code = {},
    authorizer = authorizer.new(permissions, default_permissions)
  }, { __index = _M })
end

--- Internal helper function to format a `Cookie` header string.
--
-- @param key Name of the cookie
-- @param value Value of the cookie
-- @param audience Domain cookie will be set for
-- @param expires Expiration date, should be a unix timestamp
-- @return A formatted cookie header string
-- @local
local function format_cookie(key, value, audience, expires)
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
function _M.generate_signed_jwt(self, claims)
  local jwt_payload = claims
  for k, v in pairs(self.config.payload_fields) do jwt_payload[k] = v end

  if claims.exp > (ngx.time() + self.config.ttl) then
    error("Refusing to sign a token with a longer-than-max expiry")
  end

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
local function authorize_request()
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
function _M.get_request_jwt_claims(self)
  local audience_arg = ngx.var.arg_callback or ngx.var.arg_audience

  if (audience_arg == nil) then
    ngx.log(ngx.ERR, "Required callback parameter did not exist")
    ngx.header.content_type = 'text/plain'
    return ngx.exit(ngx.HTTP_BAD_REQUEST)
  else
    local audience = uri.parse(ngx.unescape_uri(audience_arg))

    if audience == nil or audience.scheme == nil or audience.host == nil then
      ngx.log(ngx.ERR, "Could not parse callback argument")

      ngx.header.content_type = 'text/plain'
      return ngx.exit(ngx.HTTP_BAD_REQUEST)
    elseif not (audience.host):find(self.config.domain_pattern) then
      ngx.log(ngx.ERR, "Got request to generate token for an invalid host: " .. audience.host)

      ngx.header.content_type = 'text/plain'
      return ngx.exit(ngx.HTTP_BAD_REQUEST)
    end

    -- Respect request to generate custom expiry so long as it isn't longer
    -- than the default.
    local expires = ngx.time()

    if self.config.allow_custom_expiry and ngx.var.arg_expires then
      local expires_arg = tonumber(ngx.var.arg_expires)

      if expires_arg < self.config.ttl then
        expires = expires + expires_arg
      else
        error("requested expiration time is beyond the allowed max")
      end
    else
      expires = expires + self.config.ttl
    end

    local sub = ngx.var.ssl_client_serial
    local email = (ngx.var.ssl_client_s_dn):match('emailAddress=([^,]+)')

    if not self.authorizer:ids_are_authorized(audience.host, sub, email) then
      ngx.log(ngx.ERR, "Refusing to generate claims for " .. audience.host .. ", unauthorized user: " .. sub)

      ngx.header.content_type = 'text/plain'
      return ngx.exit(ngx.HTTP_FORBIDDEN)
    end

    return {
      sub = sub,
      email = email,
      aud = string.format("%s://%s", audience.scheme, audience.host),
      exp = expires
    }
  end
end

--- Request handler to serve the public key for verifying JWTs.
--
-- JWTs are signed with an asymetric key.  This route serves the public key and
-- can be used by endpoints to verify a JWT.
--
-- @return nil
function _M.handle_serve_public_key(self)
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
function _M.guard_request_with_auth(self)
  -- We look for the cookie first in a cookie, then in an `Authorization`
  -- header.
  local token;
  local authHeader = ngx.req.get_headers()['Authorization']
  local cookie = ngx.var["cookie_" .. self.config.cookie_name]

  if cookie then
    token = cookie
  elseif authHeader then
    token = authHeader:match('Bearer[ ]*(.*)')
  end

  local jwt_verify = jwt:verify(
    self.config.pub_key,
    token,
    {
      exp = validators.is_not_expired(),
      iss = validators.equals(self.config.payload_fields.iss),
      aud = validators.equals(string.format("%s://%s", ngx.var.scheme, ngx.var.http_host))
    }
  )

  if not jwt_verify['verified'] then
    ngx.log(ngx.NOTICE, "Received unverified request.  Verification failed because: " .. jwt_verify["reason"])

    local redirect_to = string.format("%s://%s%s", ngx.var.scheme, ngx.var.http_host, ngx.var.request_uri)
    local callback = string.format(
      "https://%s%s?redirect=%s",
      ngx.var.http_host,
      self.config.callback_endpoint,
      ngx.escape_uri(redirect_to)
    )

    return ngx.redirect(string.format(
      "https://%s%s?callback=%s",
      self.config.sso_endpoint,
      self.config.authorize_endpoint,
      ngx.escape_uri(callback)
    ))
  else
    ngx.var.sso_subject = jwt_verify.payload.sub
    ngx.var.sso_email = jwt_verify.payload.email
  end
end

--- Handles the callback request from the SSO endpoint.
--
-- This receives the signed JWT in a header, and sets it in a cookie. It will
-- then redirect to the original page that was accessed by the previously
-- unauthenticated client.
--
-- @return nil
function _M.handle_callback(self)
  local auth_code = ngx.var.arg_auth_code
  local status, ret = pcall(self.fetch_token_for_auth_code, self, auth_code)

  if status then
    local token = ret
    local claims = jwt:load_jwt(token)

    ngx.log(ngx.NOTICE, "Exchanged auth code for access token")

    ngx.header['Set-Cookie'] = {
      format_cookie(self.config.cookie_name, token, ngx.var.http_host, claims.payload.exp)
    }
    return ngx.redirect(ngx.unescape_uri(ngx.var.arg_redirect))
  else
    ngx.log(ngx.ERR, ret)
    ngx.exit(ngx.HTTP_BAD_REQUEST)
  end
end

--- Handles an un-authenticated exchange of an access token for an auth code.
--
-- Similar to handleCallback(), but will yield the access token in the response
-- body rather than setting it in a cookie.
--
-- @return nil
function _M.handle_auth_code_exchange(self)
  local auth_code = ngx.var.arg_auth_code
  local status, ret = pcall(self.fetch_token_for_auth_code, self, auth_code)

  if status then
    ngx.header.content_type = 'application/json'
    ngx.say(string.format('{"access_token":"%s"}', ret))
    ngx.exit(ngx.OK)
  else
    ngx.log(ngx.ERR, ret)
    ngx.exit(ngx.HTTP_BAD_REQUEST)
  end
end

--- Verify a given auth code, and if successful, return the access token
--
-- Checks that the auth code exists and has not expired. If both of these things
-- are true, returns the corresponding access token. Will also flush the store
-- of the code.
--
-- @param auth_code
-- @return string
function _M.fetch_token_for_auth_code(self, auth_code)
  if self.tokens_by_auth_code[auth_code] then
    local issued_token = self.tokens_by_auth_code[auth_code]
    self.tokens_by_auth_code[auth_code] = nil

    if issued_token.expires >= ngx.time() then
      return issued_token.access_token
    else
      error("Expired auth code!  Expired at: " .. issued_token.expires)
    end
  else
    error("Unrecognized auth code")
  end
end

--- Handle an /sso/authorize endpoint request
--
-- This function will check whether a user is authorized. If they are, it will
-- generate and sign a JWT, and redirect to the callback specified in the
-- `callback` request parameter.
--
-- @return nil
function _M.handle_authorize_request(self)
  if authorize_request() == AuthStatus.SUCCESS then
    local claims = self:get_request_jwt_claims()
    local jwt = self:generate_signed_jwt(claims)

    -- Generate an auth code and store the JWT.  User will exchange the code for
    -- the access token on callback, which will be set in the cookie.  This is
    -- convoluted, but avoids the access_token ending up in browser history.
    local auth_code = str.to_hex(random.bytes(self.config.auth_code_length, true))
    self.tokens_by_auth_code[auth_code] = {
      expires = ngx.time() + self.config.auth_code_ttl,
      access_token = jwt
    }

    -- Extract redirect URL, and append access token to args
    local url = uri.parse(ngx.unescape_uri(ngx.var.arg_callback))
    url.query.auth_code = auth_code

    return ngx.redirect(tostring(url:normalize()))
  else
    ngx.exit(ngx.HTTP_UNAUTHORIZED)
  end
end

--- Handle an /sso/token endpoint request
--
-- Check whether the user is authorized.  If they are, generate and sign a JWT
-- and serve it directly in the response body.
--
-- @return nil
function _M.handle_get_token(self)
  if authorize_request() == AuthStatus.SUCCESS then
    local token = self:generate_signed_jwt(self:get_request_jwt_claims())

    ngx.header.content_type = 'application/json'
    ngx.say(string.format('{"access_token":"%s"}', token))
    ngx.exit(ngx.OK)
  else
    ngx.exit(ngx.HTTP_UNAUTHORIZED)
  end
end

return _M