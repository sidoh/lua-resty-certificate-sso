#!/usr/bin/env bash

if [ -z "$TRAVIS_TAG" ]; then
  exit 0
fi

tag="$TRAVIS_TAG"

if [[ $str =~ ^v.*$ ]]; then
  tag="${tag:1}"
fi

luarocks upload "rockspecs/lua-resty-certificate-sso-${tag}-1.rockspec" --api-key "$LUAROCKS_API_KEY"
