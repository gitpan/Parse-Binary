#!/usr/bin/env perl
# $File: //member/autrijus/Win32-Exe/Makefile.PL $ $Author: autrijus $
# $Revision: #2 $ $Change: 9927 $ $DateTime: 2004/02/06 19:31:24 $

use inc::Module::Install;

name		('Parse-Binary');
author		('Autrijus Tang <autrijus@autrijus.org>');
abstract	('Binary data structure parser');
license		('perl');
version_from	('lib/Parse/Binary.pm');

WriteAll( sign => 1 );
