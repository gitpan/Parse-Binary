#!/usr/bin/env perl
# $File: /local/member/autrijus/Parse-Binary//Makefile.PL $ $Author: autrijus $
# $Revision: #5 $ $Change: 3922 $ $DateTime: 2004-02-17T11:18:25.380005Z $

use inc::Module::Install;

name		('Parse-Binary');
author		('Autrijus Tang <autrijus@autrijus.org>');
abstract	('Binary data structure parser');
license		('perl');
version_from	('lib/Parse/Binary.pm');
recommends	('Scalar::Util');

WriteAll( sign => 1 );
