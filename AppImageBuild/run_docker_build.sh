#!/bin/bash -x
docker run --rm -v "$(realpath ..):/build" sigbuild bash -c 'pwd; ls -l /build; bash /build/AppImageBuild/build-appimage.sh'
