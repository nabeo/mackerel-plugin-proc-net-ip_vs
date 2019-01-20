#!/bin/sh
set -e

release_tag=$1
if [ -z "$release_tag" ] ; then
  echo "please set release tag"
  exit 1
fi
git tag -l | grep "$release_tag" || git tag "$release_tag"

repo_root=$(git rev-parse --show-toplevel)
if [ -z "$repo_root" ]; then
  echo "not git repository"
  exit 1
fi

github_token=$(git config --get github.token)
if [ -z "${github_token}" ]; then
  echo "please set github toke"
  exit 1
fi

plugin_name=$(basename "$repo_root")
repository=$(basename "$(dirname "$repo_root")")
goxz_cmd=$(command -v goxz)
test ! -z "$goxz_cmd" || go get -uv github.com/Songmu/goxz/cmd/goxz
ghr_cmd=$(command -v ghr)
test ! -z "$ghr_cmd" || go get -uv github.com/tcnksm/ghr

echo "release : $repository/$plugin_name @ $release_tag"

"$goxz_cmd" -d "$repo_root/dist/$release_tag" -z -os linux -arch amd64,386
"$ghr_cmd" -u "$repository" -r "$plugin_name" "$release_tag" "$repo_root/dist/$release_tag"
