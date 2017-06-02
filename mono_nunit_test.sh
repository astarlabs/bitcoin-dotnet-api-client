#!/usr/bin/env bash
#
# Generated by: https://github.com/swagger-api/swagger-codegen.git
#

echo "[INFO] remove bin/Debug/SwaggerClientTest.dll"
rm src/AStar.Test/bin/Debug/AStar.Test.dll 2> /dev/null

echo "[INFO] install NUnit runners via NuGet"
wget -nc https://nuget.org/nuget.exe
cert-sync /etc/ssl/certs/ca-certificates.crt
mono nuget.exe install src/AStar.Test/packages.config -o packages

echo "[INFO] Install NUnit runners via NuGet"
mono  nuget.exe install NUnit.Runners -Version 2.6.4 -OutputDirectory packages 

echo "[INFO] Build the solution and run the unit test"
msbuild AStar.sln && \
    mono --debug ./packages/NUnit.Runners.2.6.4/tools/nunit-console.exe src/AStar.Test/bin/Debug/AStar.Test.dll