#!/usr/bin/env perl
# $File: //local/member/autrijus/Parse-Binary/Makefile.PL $ $Author: autrijus $
# $Revision: #4 $ $Change: 1130 $ $DateTime: 2004-02-17T15:40:29.640821Z $

use inc::Module::Install;

name		('Parse-Binary');
author		('Autrijus Tang <autrijus@autrijus.org>');
abstract	('Binary data structure parser');
license		('perl');
version_from	('lib/Parse/Binary.pm');
recommends	('Scalar::Util');

WriteAll( sign => 1 );
