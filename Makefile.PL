#!/usr/bin/perl

use inc::Module::Install;

name		('Parse-Binary');
author		('Audrey Tang <cpan@audreyt.org>');
abstract	('Binary data structure parser');
license		('perl');
version_from	('lib/Parse/Binary.pm');
recommends	('Scalar::Util');

WriteAll( sign => 1 );
