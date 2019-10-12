local _M = {}

--- Create a new authorizer instance
--
-- @param permissions a table of permissions keyed on IDs
-- @param default_permissions permissions returned if ID is not present
-- @return instance of module
function _M.new(permissions, default_permissions)
  return setmetatable({
    permissions = permissions,
    default_permissions = default_permissions
  }, { __index = _M })
end

--- Check if a single ID is authorized.
--
-- @param audience the audience to check if the ID has access to
-- @param id the ID to check
-- @return true iff the ID is authorized to access the audience
function _M.id_is_authorized(self, audience, id)
  local permissions = self.permissions[id] or self.default_permissions

  if permissions == nil then
    return false
  else
    return permissions["*"] == true or permissions[audience] == true
  end
end

--- Check if any of the IDs are authorized
--
-- @param audience
-- @varargs IDs
-- @return true iff any of the IDs are authorized
function _M.ids_are_authorized(self, audience, ...)
  local ids = { ... }

  for _,v in ipairs(ids) do
    if self:id_is_authorized(audience, v) then
      return true
    end
  end

  return false
end

return _M