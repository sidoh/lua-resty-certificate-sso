# lua-resty-certificate-sso [![Build Status](https://travis-ci.org/sidoh/lua-resty-certificate-sso.svg?branch=master)](https://travis-ci.org/sidoh/lua-resty-certificate-sso)
A library for enabling a local client certificate-based SSO provider using [OpenResty](https://openresty.org/en/).

## Setup

#### Set up client certificates

This is a fair amount of effort on its own, but is outside the scope of this README.  We'll assume that you have client certificates generated and issued to all of the devices you want to use.

#### Install the library with `luarocks`:

```
sudo /path/to/luajit/luarocks install install lua-resty-certificate-sso
```

#### Configure nginx/OpenResty

A sample configuration is provided in the [examples directory](./examples).

The key changes are:

1. Generate an RSA key.  This will be used for signing the JWT tokens used for authentication:
   ```bash
   openssl req -newkey rsa:4096 -nodes -keyout jwt.key
   openssl rsa -in jwt.key -pubout > jwt.pub
   ```
2. Add and initialize a shared dict under the main `http` block:
   ```nginx
   http {
     ...
     lua_shared_dict certificate_sso 64k;

     init_by_lua_block {
       certificate_sso = (require "resty.certificate-sso").new({
         -- These are the keys we generated in the previous step
         private_key_file = '/etc/nginx/ssl/jwt/jwt.key',
         pub_key_file = '/etc/nginx/ssl/jwt/jwt.pub',
         sso_endpoint = "sso.example.com",
         audience_domain = "example.com"
         -- Other configs go here...
       })
     }
     ...
   }
   ```
3. Set up the SSO server endpoint.  See [auth.example.com.conf](./examples/sites-available/auth.example.com.conf) for an example.
4. Include the SSO snippet scripts on any server you want to guard using SSO auth.  See [site.example.com.conf](./examples/sites-available/auth.example.com.conf) for an example.  This is where you should have `ssl_verify_client` set to `on`.
5. Restart openresty, and you should be set!  Check that you're not able to access pages without a valid client certificate.

## Configuration

Much of the behavior of this library is configurable.  Check the module `new` definition for a complete list.

## JWT Claims

Issued JWTs contain the following claims:

1. `exp` - timestamp the JWT expires.  This is checked as part of the verification process.  Expired JWTs must be refreshed.
2. `iss` - issuer.  By default, this will be set to the `sso_endpoint` configuration.  It's overridable using the `payload_fields` config.
3. `aud` - audience.  This will be set to the site we generated the JWT for.
4. `sub` - subject.  Will be set to the client certificate serial number to ensure this is set to a unique identifier.
5. `email` - email address (not always set).  We attempt to extract an email address from the client certificate's subject DN.  If one cannot be found, this claim won't be set.
