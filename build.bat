:: Generated by: https://github.com/swagger-api/swagger-codegen.git
::

@echo off

SET CSCPATH=%SYSTEMROOT%\Microsoft.NET\Framework\v4.0.30319

if not exist ".\nuget.exe" powershell -Command "(new-object System.Net.WebClient).DownloadFile('https://nuget.org/nuget.exe', '.\nuget.exe')"
.\nuget.exe install src\AStar\packages.config -o packages

if not exist ".\bin" mkdir bin

copy packages\Newtonsoft.Json.8.0.3\lib\net45\Newtonsoft.Json.dll bin\Newtonsoft.Json.dll
copy packages\RestSharp.105.1.0\lib\net45\RestSharp.dll bin\RestSharp.dll
copy packages\jose-jwt.2.3.0\lib\net40\jose-jwt.dll bin\jose-jwt.dll
copy packages\BouncyCastle.1.8.1\lib\BouncyCastle.Crypto.dll bin\BouncyCastle.Crypto.dll
%CSCPATH%\csc  /reference:bin\BouncyCastle.Crypto.dll;bin\jose-jwt.dll;bin\Newtonsoft.Json.dll;bin\RestSharp.dll;System.ComponentModel.DataAnnotations.dll  /target:library /out:bin\AStar.dll /recurse:src\AStar\*.cs /doc:bin\AStar.xml

