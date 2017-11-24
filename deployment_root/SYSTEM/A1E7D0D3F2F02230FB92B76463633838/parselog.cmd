::::::::::::::::::::::::::::::::::::::::::::::::::
:: IBM Confidential
::
:: (C) Copyright IBM Corp. 2014 All Rights Reserved.
::
:: All Rights Reserved.
:: The source code for this program is not published or otherwise
:: divested of its trade secrets, irrespective of what has been
:: deposited with the U.S. Copyright Office.

::
:: Parse problem deterination log file into simple format
::

echo off
if defined ProgramW6432 goto winx64

set PrgFiles=%ProgramFiles%
goto parselog

:winx64
set PrgFiles=%ProgramW6432%

:parselog


:: Default installation location
set javaexe=%PrgFiles%\ibm\sdp\jdk\bin\java
set corejar=%prgFiles%\ibm\sdp\majordomo\lib\core.jar
if not exist "%corejar%" goto corenotfound
echo on
"%javaexe%" -cp "%corejar%" com.ibm.rational.test.lt.core.utils.PDLParse %1 %2
goto end


:: Core library not found
:corenotfound
echo on
echo Could not find core library

:end
