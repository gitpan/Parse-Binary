package Parse::Binary::FixedFormat;

use strict;
our $VERSION = "0.02";

sub new {
    my ($class, $layout) = @_;
    my $self;
    if (ref $layout eq "HASH") {
	require Parse::Binary::FixedFormat::Variants;
	$self = new Parse::Binary::FixedFormat::Variants $layout;
    } else {
	$self = { Names=>[], Count=>[], Format=>"" };
	bless $self, $class;
	$self->parse_fields($layout) if $layout;
    }
    return $self;
}

sub parse_fields {
    my ($self,$fmt) = @_;
    foreach my $fld (@$fmt) {
	my ($name, $format, $count, $group) = split /\s*:\s*/,$fld;
	push @{$self->{Names}}, $name;
	push @{$self->{Count}}, $count;
	push @{$self->{Group}}, $group;
	if (defined $count) {
	    push @{$self->{Format}||=[]}, "($format)$count";
	}
	else {
	    push @{$self->{Format}||=[]}, $format;
	}
    }
}

sub _format {
    my $format = join('', @{$_[0]{Format}||=[]});
    $format =~ s/\((.*?)\)(?:(\d+)|(\*))/$1 x ($3 ? 1 : $2)/eg if $] < 5.008;
    return $format;
}


sub unformat {
    my ($self,$frec) = @_;
    my @flds = unpack $self->_format, $frec;
    my $rec = {};
    foreach my $i (0 .. $#{$self->{Names}}) {
	my $name = $self->{Names}[$i];
	if (defined(my $count = $self->{Count}[$i])) {
	    next unless $count;

	    my $group = $self->{Group}[$i];
	    if ($count eq '*') {
		$count = @flds;
		$group ||= 1;
	    }

	    if ($group) {
		my @data = splice @flds, 0, $count;
		my $pad = 0;
		$pad = length($1) if $self->{Format}[$i] =~ /(X+)/;
		while (@data) {
		    push @{$rec->{$name}}, [ splice(@data, 0, $group) ];
		    substr($rec->{$name}[-1][-1], -$pad, $pad, '') if $pad;
		}
	    }
	    else {
		@{$rec->{$name}} = splice @flds, 0, $count;
	    }
	} else {
	    $rec->{$name} = shift @flds;
	}
    }
    return $rec;
}

sub format {
    my ($self,$rec) = @_;
    my @flds;
    my $i = 0;
    foreach my $name (@{$self->{Names}}) {
	if ($self->{Count}[$i]) {
	    push @flds,map {ref($_) ? @$_ : $_} @{$rec->{$name}};
	} else {
	    push @flds,$rec->{$name};
	}
    	$i++;
    } 
    my $frec = pack $self->_format, @flds;
    return $frec;
}

sub blank {
    my $self = shift;
    my $rec = $self->unformat(pack($self->_format,
				   unpack($self->_format,
					  '')));
    return $rec;
}

=head1 NAME

Parse::Binary::FixedFormat - Convert between fixed-length fields and hashes

=head1 SYNOPSIS

   use Parse::Binary::FixedFormat;

   my $tarhdr =
      new Parse::Binary::FixedFormat [ qw(name:a100 mode:a8 uid:a8 gid:a8 size:a12
			         mtime:a12 chksum:a8 typeflag:a1 linkname:a100
				 magic:a6 version:a2 uname:a32 gname:a32
			         devmajor:a8 devminor:a8 prefix:a155) ];
   my $buf;
   read TARFILE, $buf, 512;

   # create a hash from the buffer read from the file
   my $hdr = $tarhdr->unformat($buf);   # $hdr gets a hash ref

   # create a flat record from a hash reference
   my $buf = $tarhdr->format($hdr);     # $hdr is a hash ref

   # create a hash for a new record
   my $newrec = $tarhdr->blank();

=head1 DESCRIPTION

B<Parse::Binary::FixedFormat> can be used to convert between a buffer with
fixed-length field definitions and a hash with named entries for each
field.  The perl C<pack> and C<unpack> functions are used to perform
the conversions.  B<Parse::Binary::FixedFormat> builds the format string by
concatenating the field descriptions and converts between the lists
used by C<pack> and C<unpack> and a hash that can be reference by
field name.

=head1 METHODS

B<Parse::Binary::FixedFormat> provides the following methods.

=head2 new

To create a converter, invoke the B<new> method with a reference to a
list of field specifications.

    my $cvt =
        new Parse::Binary::FixedFormat [ 'field-name:descriptor:count', ... ];

Field specifications contain the following information.

=over 4

=item field-name

This is the name of the field and will be used as the hash index.

=item descriptor

This describes the content and size of the field.  All of the
descriptors get strung together and passed to B<pack> and B<unpack> as
part of the template argument.  See B<perldoc -f pack> for information
on what can be specified here.

Don't use repeat counts in the descriptor except for string types
("a", "A", "h, "H", and "Z").  If you want to get an array out of the
buffer, use the C<count> argument.

=item count

This specifies a repeat count for the field.  If specified as a
non-zero value, this field's entry in the resultant hash will be an
array reference instead of a scalar.

=back

=head2 unformat

To convert a buffer of data into a hash, pass the buffer to the
B<unformat> method.

    $hashref = $cvt->unformat($buf);

Parse::Binary::FixedFormat applies the constructed format to the buffer with
C<unpack> and maps the returned list of elements to hash entries.
Fields can now be accessed by name though the hash:

    print $hashref->{field-name};
    print $hashref->{array-field}[3];

=head2 format

To convert the hash back into a fixed-format buffer, pass the hash
reference to the B<format> method.

    $buf = $cvt->format($hashref);

=head2 blank


To get a hash that can be used to create a new record, call the
B<blank> method.

    $newrec = $cvt->blank();

=head1 ATTRIBUTES

Each Parse::Binary::FixedFormat instance contains the following attributes.

=over 4

=item Names

Names contains a list of the field names for this variant.

=item Count

Count contains a list of occurrence counts.  This is used to indicate
which fields contain arrays.

=item Format

Format contains the template string for the Perl B<pack> and B<unpack>
functions.

=back

=head1 AUTHORS

Autrijus Tang E<lt>autrijus@autrijus.orgE<gt>

Based on Data::FixedFormat, written by Thomas Pfau <pfau@nbpfaus.net>
http://nbpfaus.net/~pfau/.

=head1 COPYRIGHT

Copyright 2004 by Autrijus Tang E<lt>autrijus@autrijus.orgE<gt>.

Copyright (C) 2000,2002 Thomas Pfau.  All rights reserved.

This module is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation; either version 2 of the License, or (at your
option) any later version.

This library is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Library General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software Foundation,
Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.

=cut
