# $File: /local/member/autrijus/Parse-Binary//lib/Parse/Binary.pm $ $Author: autrijus $
# $Revision: #36 $ $Change: 3944 $ $DateTime: 2004-02-17T19:40:00.242275Z $

package Parse::Binary;
$Parse::Binary::VERSION = '0.06';

use bytes;
use strict;
use Parse::Binary::FixedFormat;

=head1 NAME

Parse::Binary - Unpack binary data structures into object hierarchies

=head1 VERSION

This document describes version 0.06 of Parse::Binary, released
February 18, 2004.

=head1 SYNOPSIS

# This class represents a Win32 F<.ico> file:

    package IconFile;
    use base 'Parse::Binary';
    use constant FORMAT => (
	Magic		=> 'a2',
	Type		=> 'v',
	Count		=> 'v',
	'Icon'		=> [ 'a16', '{$Count}', 1 ],
	Data		=> 'a*',
    );

# An individual icon resource:

    package Icon;
    use base 'Parse::Binary';
    use constant FORMAT => (
	Width		=> 'C',
	Height		=> 'C',
	ColorCount	=> 'C',
	Reserved	=> 'C',
	Planes		=> 'v',
	BitCount	=> 'v',
	ImageSize	=> 'V',
	ImageOffset	=> 'v',
    );
    sub Data {
	my ($self) = @_;
	return $self->parent->substr($self->ImageOffset, $self->ImageSize);
    }

# Simple F<.ico> file dumper that uses them:

    use IconFile;
    my $icon_file = IconFile->new('input.ico');
    foreach my $icon ($icon_file->members) {
	print "Dimension: ", $icon->Width, "x", $icon->Height, $/;
	print "Colors: ", 2 ** $icon->BitCount, $/;
	print "Image Size: ", $icon->ImageSize, " bytes", $/;
	print "Actual Size: ", length($icon->Data), " bytes", $/, $/;
    }
    $icon_file->write('output.ico'); # save as another .ico file

=head1 DESCRIPTION

This module makes parsing binary data structures much easier, by serving
as a base class for classes that represents the binary data, which may
contain objects of other classes to represent parts of itself.

Documentation is unfortunately a bit lacking at this moment.  Please read
the tests and source code of L<Parse::AFP> and L<Win32::Exe> for examples
of using this module.

=cut

use constant PROPERTIES	    => qw(
    %struct $filename $size $parent @siblings %children
    $output $lazy $iterator $iterated
);
use constant ENCODED_FIELDS => ( 'Data' );
use constant FORMAT	    => ( Data => 'a*' );
use constant SUBFORMAT	    => ();
use constant DEFAULT_ARGS   => ();
use constant DELEGATE_SUBS  => ();
use constant DISPATCH_TABLE => ();

use constant DISPATCH_FIELD => undef;
use constant BASE_CLASS	    => undef;
use constant ENCODING	    => undef;
use constant PADDING	    => undef;

eval { require Scalar::Util; 1 }
    or *Scalar::Util::weaken = sub { 1 };

foreach my $item (+PROPERTIES) {
    no strict 'refs';
    my ($sigil, $name) = split(//, $item, 2);
    *{"$name"} =
	($sigil eq '$') ? sub { $_[0]{$name} } :
	($sigil eq '@') ? sub { wantarray ? @{$_[0]{$name}||=[]} : ($_[0]{$name}||=[]) } :
	($sigil eq '%') ? sub { $_[0]{$name}||={} } :
	die "Unknown sigil: $sigil";
    *{"set_$name"} =
	($sigil eq '$') ? sub { $_[0]->{$name} = $_[1] } :
	($sigil eq '@') ? sub { @{$_[0]->{$name}||=$_[1]||[]} = @{$_[1]||[]} } :
	($sigil eq '%') ? sub { %{$_[0]->{$name}||=$_[1]||{}} = %{$_[1]||{}} } :
	die "Unknown sigil: $sigil";
}

### Constructors ###

sub new {
    my ($self, $input, $attr) = @_;
    my $class = $self->class;
    $class->init;

    $attr ||= {};
    $attr->{filename} ||= $input unless ref $input;

    my $obj = $class->spawn;
    %$obj = (%$obj, %$attr);

    my $data = $obj->read_data($input);
    $obj->load($data, $attr);

    my $load_sub = sub {
	$obj->make_members unless $obj->iterator;
    };

    if ($obj->lazy) {
	$obj->set_lazy($load_sub);
    }
    else {
	&$load_sub;
    }

    return $obj;
}

sub dispatch_field {
    return undef;
}

sub init {
    my ($class) = @_;

    no strict 'refs';
    return if ${"$class\::init_done"};

    my @args = $class->default_args;
    *{"$class\::default_args"} = sub { @args };

    my $delegate_subs = $class->delegate_subs;
    if (defined(&{"$class\::DELEGATE_SUBS"})) {
	$delegate_subs = { $class->DELEGATE_SUBS };
    }
    *{"$class\::delegate_subs"} = sub { $delegate_subs };

    while (my ($subclass, $methods) = each %$delegate_subs) {
	$methods = [ $methods ] unless ref $methods;
	foreach my $method (grep length, @$methods) {
	    *{"$class\::$method"} = sub {
		goto &{$_[0]->require_class($subclass)->can($method)};
	    };
	}
    }

    my $dispatch_table = $class->dispatch_table;
    if (defined(&{"$class\::DISPATCH_TABLE"})) {
	$dispatch_table = { $class->DISPATCH_TABLE };
    }
    *{"$class\::dispatch_table"} = sub { $dispatch_table };

    my $dispatch_field = undef;
    if (defined(&{"$class\::DISPATCH_FIELD"})) {
	$dispatch_field = $class->DISPATCH_FIELD;
    }
    *{"$class\::dispatch_field"} = sub { $dispatch_field };

    my @format = $class->format_list;
    if (my @subformat = $class->subformat_list) {
	my @new_format;
	while (my ($field, $format) = splice(@format, 0, 2)) {
	    if ($field eq 'Data') {
		push @new_format, @subformat;
	    }
	    else {
		push @new_format, ($field => $format);
	    }
	}
	@format = @new_format;
    }
    my @format_list = @format;
    *{"$class\::format_list"} = sub { @format_list };

    my (@fields, @formats, @pack_formats, $underscore_count);
    my (%field_format, %field_pack_format);
    my (%field_parser, %field_packer, %field_length);
    my (@member_fields, %member_class);
    while (my ($field, $format) = splice(@format, 0, 2)) {
	if ($field eq '_') {
	    # "we don't care" fields 
	    $underscore_count++;
	    $field = "_${underscore_count}_$class";
	    $field =~ s/:/_/g;
	}

	if (ref $format) {
	    $member_class{$field} = $class->classname($field);
	    $field =~ s/:/_/g;
	    $member_class{$field} = $class->classname($field);
	    $class->require($member_class{$field});
	    push @member_fields, $field;
	}
	else {
	    $format = [ $format ];
	}

	push @fields, $field;

	my $string = join(':', $field, @$format);
	$field_format{$field} = [ @$format ];
	if (!grep /\{/, @$format) {
	    $field_length{$field} = length(pack($format->[0], 0));
	    $field_parser{$field} = Parse::Binary::FixedFormat->new( [ $string ] );
	}
	push @formats, $string;

	s/\s*X\s*//g for @$format;
	my $pack_string = join(':', $field, @$format);
	$field_pack_format{$field} = [ @$format ];
	$field_packer{$field} = Parse::Binary::FixedFormat->new( [ $pack_string ] );
	push @pack_formats, $pack_string;
    }

    *{"$class\::fields"} = sub { @fields };
    *{"$class\::formats"} = sub { @formats };
    *{"$class\::member_fields"} = sub { @member_fields };
    *{"$class\::member_class"} = sub { $member_class{$_[1]} };
    *{"$class\::pack_formats"} = sub { @pack_formats };
    *{"$class\::field_format"} = sub { $field_format{$_[1]}[0] };
    *{"$class\::field_pack_format"} = sub { $field_pack_format{$_[1]}[0] };
    *{"$class\::field_length"} = sub { $field_length{$_[1]} };

    my $parser = $class->make_formatter(@formats);
    my $packer = $class->make_formatter(@pack_formats);
    *{"$class\::parser"} = sub { $parser };
    *{"$class\::packer"} = sub { $packer };
    *{"$class\::field_parser"} = sub {
	my ($self, $field) = @_;
	$field_parser{$field} || do {
	    Parse::Binary::FixedFormat->new( [
		$self->eval_format(
		    $self->struct,
		    join(':', $field, @{$field_format{$field}}),
		),
	    ] );
	};
    };
    *{"$class\::field_packer"} = sub { $field_packer{$_[1]} };
    *{"$class\::has_field"} = sub { $field_packer{$_[1]} };

    my %enc_fields = map { ($_ => 1) } $class->ENCODED_FIELDS;

    foreach my $field (@fields) {
	next if defined &{"$class\::$field"};

	if ($enc_fields{$field} and my $encoding = $class->ENCODING) {
	    require Encode;

	    *{"$class\::$field"} = sub {
		my ($self) = @_;
		return Encode::decode($encoding => $self->field($field));
	    };
	    *{"$class\::Set$field"} = sub {
		my ($self, $data) = @_;
		$self->set_field($field, Encode::encode($encoding => $data));
	    };
	    next;
	}

	*{"$class\::$field"} = sub { $_[0]->field($field) };
	*{"$class\::Set$field"} = sub { $_[0]->set_field($field, $_[1]) };
    }

    ${"$class\::init_done"} = 1;
}

sub initialize {
    return 1;
}

### Miscellanous ###

sub field {
    my ($self, $field) = @_;
    return $self->struct->{$field};
}

sub set_field {
    my ($self, $field, $data) = @_;
    $self->struct->{$field} = $data;
}

sub classname {
    my ($self, $class) = @_;
    return undef unless $class;

    $class =~ s/__/::/g;

    my $base_class = $self->BASE_CLASS or return $class;
    return $base_class if $class eq '::BASE::';

    return "$base_class\::$class";
}

sub member_fields {
    return ();
}

sub dispatch_class {
    my ($self, $field) = @_;
    my $table = $self->dispatch_table;
    my $class = exists($table->{$field}) ? $table->{$field} : $table->{'*'};

    $class = &$class($self, $field) if UNIVERSAL::isa($class, 'CODE');
    return $self->classname($class);
}

sub require {
    my ($class, $module) = @_;
    return unless defined $module;

    my $file = "$module.pm";
    $file =~ s{::}{/}g;

    return $module if (eval { require $file; 1 });
    die $@ unless $@ =~ /^Can't locate /;
    return;
}

sub require_class {
    my ($class, $subclass) = @_;
    return $class->require($class->classname($subclass));
}

sub format_list {
    my ($self) = @_;
    return $self->FORMAT;
}

sub subformat_list {
    my ($self) = @_;
    $self->SUBFORMAT ? $self->SUBFORMAT : ();
}

sub default_args {
    my ($self) = @_;
    $self->DEFAULT_ARGS ? $self->DEFAULT_ARGS : ();
}

sub dispatch_table {
    my ($self) = @_;
    $self->DISPATCH_TABLE ? { $self->DISPATCH_TABLE } : {};
}

sub delegate_subs {
    my ($self) = @_;
    $self->DELEGATE_SUBS ? { $self->DELEGATE_SUBS } : {};
}

sub class {
    my ($self) = @_;
    return(ref($self) || $self);
}

sub make_formatter {
    my ($self, @formats) = @_;
    return Parse::Binary::FixedFormat->new( $self->make_format(@formats) );
}

sub make_format {
    my ($self, @formats) = @_;
    return \@formats unless grep /\{/, @formats;

    my @prefix;
    foreach my $format (@formats) {
	last if $format =~ /\{/;
	push @prefix, $format;
    }
    return {
	Chooser => sub { $self->chooser(@_) },
	Formats => [ \@prefix, \@formats ],
    };
}

sub chooser {
    my ($self, $rec, $obj, $mode) = @_;
    my $idx = @{$obj->{Layouts}};
    my @format = $self->eval_format($rec, @{$obj->{Formats}[1]});
    $obj->{Layouts}[$idx] = $self->make_formatter(@format);
    return $idx;
}

sub eval_format {
    my ($self, $rec, @format) = @_;
    foreach my $key (sort keys %$rec) {
	s/\$$key\b/$rec->{$key}/ for @format;
    }
    !/\$/ and s/\{(.*?)\}/$1/eeg for @format;
    die $@ if $@;
    return @format;
}

sub padding {
    return '';
}

sub load_struct {
    my ($self, $data) = @_;
    local $SIG{__WARN__} = sub {};
    $self->{struct} = $self->parser->unformat($$data . $self->padding, $self->lazy);
}

sub load_size {
    my ($self, $data) = @_;
    $self->set_size(length($$data));
    return 1;
}

sub lazy_load {
    my ($self) = @_;
    ref(my $sub = $self->lazy) or return;
    $self->set_lazy(1);
    goto &$sub;
}

sub load {
    my ($self, $data, $attr) = @_;
    return $self unless defined $data;
    $self->class->init;

    $self->load_struct($data);
    $self->load_size($data);

    if (my $field = $self->dispatch_field) {
	my $value = $self->$field;
	my $subclass = $self->dispatch_class($value);
	if ($subclass and $subclass ne $self->class) {
	    $self->require($subclass);
	    bless($self, $subclass);
	    $self->load($data, $attr);
	    $self->make_members unless $self->iterator;
	}
    }

    return $self;
}

sub spawn {
    my ($self, %args) = @_;
    my $class = $self->class;
    $class->init;

    if (my $subclass = $self->classname($args{Class})) {
	delete $args{Class};
	$self->require($subclass);
	return $subclass->spawn(%args);
    }

    return bless({}, $class) unless %args or $self->default_args;

    my %hash;
    %args = (%args, $self->default_args);
    foreach my $field ($self->fields) {
	$hash{$field} = $args{$field};
    }

    foreach my $super_class ($class->superclasses) {
	my $field = $super_class->dispatch_field or next;
	my $table = $super_class->dispatch_table or next;
	next if defined $hash{$field};
	foreach my $code (sort keys %$table) {
	    $class->is_type($table->{$code}) or next;
	    $hash{$field} = $code;
	    last;
	}
    }

    my $obj = bless({}, $class);
    $obj->set_struct(\%hash);
    $obj->refresh;
    return $obj;
}

sub spawn_sibling {
    my ($self, %args) = @_;
    my $parent = $self->parent or die "$self has no parent";

    my $obj = $self->spawn(%args);
#    $obj->set_lazy($self->lazy);
    $obj->set_parent($parent);
    $obj->set_output($self->output);
    $obj->set_siblings($self->{siblings});
    $obj->set_size(length($obj->dump));
    $obj->initialize;

    return $obj;
}

sub sibling_index {
    my ($self, $obj) = @_;
    $obj ||= $self;

    my @siblings = $self->siblings;
    foreach my $index (0 .. $#siblings) {
	return $index if $obj == $siblings[$index];
    }

    return undef;
}

sub prepend_obj {
    my ($self, %args) = @_;
    my $obj = $self->spawn_sibling(%args);

    $self->set_siblings([
	map { (($_ == $self) ? $obj : ()), $_ } $self->siblings
    ]);
    return $obj;
}

sub append_obj {
    my ($self, %args) = @_;
    my $obj = $self->spawn_sibling(%args);

    $self->set_siblings([
	map { $_, (($_ == $self) ? $obj : ()) } $self->siblings
    ]);
    return $obj;
}

sub remove {
    my ($self, %args) = @_;
    my $siblings = $self->siblings;
    splice(@$siblings, $self->sibling_index, 1);

    Scalar::Util::weaken($self->{parent});
}

sub read_data {
    my ($self, $data) = @_;
    return undef unless defined $data;
    return \($data->dump) if UNIVERSAL::can($data, 'dump');
    return $data if UNIVERSAL::isa($data, 'SCALAR');
    return \($self->read_file($data));
}

sub read_file {
    my ($self, $file) = @_;

    local *FH; local $/;
    open FH, "< $file" or die "Cannot open $file for reading: $!";
    binmode(FH);

    return scalar <FH>;
}

sub has_members {
    my ($self) = @_;
    return $self->member_fields;
}

sub make_members {
    my ($self) = @_;

    $self->has_members or return;
    $self->set_children();

    foreach my $field ($self->member_fields) {
	my ($format) = $self->eval_format(
	    $self->struct,
	    $self->field_pack_format($field),
	);

	my $members = [ map {
	    $self->new_member( $field, \pack($format, @$_) )
	} $self->validate_memberdata($field) ];
	$self->set_field_children( $field, $members );
    }
}

sub set_members {
    my ($self, $field, $members) = @_;
    $field =~ s/:/_/g;
    $self->set_field_children(
	$field,
	[ map { $self->new_member( $field, $_ ) } @$members ],
    );
}

sub set_field_children {
    my ($self, $field, $data) = @_;
    my $children = $self->field_children($field);
    @$children = @$data;
    return $children;
}

sub field_children {
    my ($self, $field) = @_;
    my $children = ($self->children->{$field} ||= []);
    # $_->lazy_load for @$children;
    return(wantarray ? @$children : $children);
}

sub validate_memberdata {
    my ($self, $field) = @_;
    return @{$self->field($field)||[]};
}

sub first_member {
    my ($self, $type) = @_;
    $self->lazy_load;

    return undef unless $self->has_members;
    foreach my $field ($self->member_fields) {
	foreach my $member ($self->field_children($field)) {
	    return $member if $member->is_type($type);
	}
    }
    return undef;
}

sub next_member {
    my ($self, $type) = @_;
    return undef unless $self->has_members;

    if ($self->lazy and !$self->iterated) {
	while (my $member = $self->make_next_member) {
	    return $member if $member->is_type($type);
	}
	$self->set_iterated(1);
	return;
    }

    $self->{_next_member}{$type} ||= $self->members($type);

    shift(@{$self->{_next_member}{$type}})
	|| undef($self->{_next_member}{$type});
}

sub make_next_member {
    my ($self) = @_;

    $self->has_members or return;

    if (ref($self->lazy)) {
	$self->set_children;
	$self->set_iterator({ field_idx => 0, item_idx => 0 });
	$self->lazy_load;
    }

    my $iterator = $self->iterator or return; 

    my ($field_idx, $item_idx, $format)
	= @{$iterator}{qw(field_idx item_idx format)};

    my @fields = $self->member_fields;
    if ($field_idx > $#fields) {
	$self->set_iterator;
	return;
    }

    my $field = $fields[$field_idx] or return;
    $format ||= ($self->eval_format(
	$self->struct,
	$self->field_pack_format($field),
    ))[0];

    my $items = $self->field($field);
    if ($item_idx > $#$items) {
	$self->set_iterator({
	    field_idx   => ++$field_idx,
	    item_idx    => 0,
	    format	=> undef,
	});
	goto &{$self->can('make_next_member')};
    }

    my $item = $items->[$item_idx];
    $self->set_iterator({
	field_idx   => $field_idx,
	item_idx    => ++$item_idx,
	format	    => $format,
    });

    $item = &$item if UNIVERSAL::isa($item, 'CODE');

    if (!$self->valid_memberdata($item)) {
	goto &{$self->can('make_next_member')};
    }

    my $member = $self->new_member( $field, \pack($format, @$item) );
    my $children = $self->field_children($field);
    push @$children, $member;
    $member->lazy_load;
    return $member;
}

sub members {
    my ($self, $type) = @_;
    $self->lazy_load;

    my @members = map {
	grep { $type ? $_->is_type($type) : 1 } $self->field_children($_)
    } $self->member_fields;
    wantarray ? @members : \@members;
}

sub members_recursive {
    my ($self, $type) = @_;
    my @members = (
	( $self->is_type($type) ? $self : () ),
	map { $_->members_recursive($type) } $self->members
    );
    wantarray ? @members : \@members;
}

sub new_member {
    my ($self, $field, $data) = @_;
    my $obj = $self->member_class($field)->new($data);

    $obj->set_siblings(scalar $self->field_children($field));
    $obj->set_parent($self);
    $obj->set_output($self->output);
    $obj->initialize;

    return $obj;
}

sub valid_memberdata {
    length($_[-1][0])
}

sub dump {
    my ($self) = @_;
    local $SIG{__WARN__} = sub {};
    return $self->packer->format($self->struct);
}

sub write {
    my ($self, $file) = @_;

    if (ref($file)) {
	$$file = $self->dump;
    }
    elsif (!defined($file) and my $fh = $self->output) {
	print $fh $self->dump;
    }
    else {
	$file = $self->filename unless defined $file;
	$self->write_file($file, $self->dump) if defined $file;
    }
}

sub write_file {
    my ($self, $file, $data) = @_;
    local *FH;
    open FH, "> $file" or die "Cannot open $file for writing: $!";
    binmode(FH);
    print FH $data;
};

sub superclasses {
    my ($self) = @_;
    my $class = $self->class;

    no strict 'refs';
    return @{"$class\::ISA"};
}

sub is_type {
    my ($self, $type) = @_;
    return 1 unless defined $type;

    my $class = ref($self) || $self;

    $type =~ s/__/::/g;
    $type =~ s/[^\w:]//g;
    return 1 if ($class =~ /::$type$/);

    no strict 'refs';
    foreach my $super_class ($class->superclasses) {
	return 1 if $super_class->is_type($type);
    };
}

sub refresh {
    my ($self) = @_;

    foreach my $field ($self->member_fields) {
	my $parser = $self->field_parser($field);
	my $padding = $self->padding;

	local $SIG{__WARN__} = sub {};
	$self->set_field(
	    $field, [
		map {
		    $parser->unformat( $_->dump . $padding)->{$field}[0]
		} @{$self->children->{$field}||[]},
	    ],
	);
	$self->validate_memberdata;
    }

    $self->refresh_parent;
}

sub refresh_parent {
    my ($self) = @_;
    my $parent = $self->parent or return;
    $parent->refresh;
}

sub first_parent {
    my ($self, $type) = @_;
    return $self if $self->is_type($type);
    my $parent = $self->parent or return;
    return $parent->first_parent($type);
}

sub substr {
    my $self    = shift;
    my $data    = $self->Data;
    my $offset  = shift(@_) - ($self->size - length($data));
    my $length  = @_ ? shift(@_) : (length($data) - $offset);
    my $replace = shift;

    # XXX - Check for "substr outside string"
    return if $offset > length($data);

    # Fetch a range
    return substr($data, $offset, $length) if !defined $replace;

    # Substitute a range
    substr($data, $offset, $length, $replace);
    $self->SetData($data);
}

sub set_output_file {
    my ($self, $file) = @_;

    require IO::File;
    my $fh = IO::File->new("> $file") or die $!;
    binmode($fh);
    $self->set_output($fh);
}

sub callback {
    my $self  = shift;
    my $types = shift or return;

    my ($pkg, $level);
    while ($pkg = caller($level++)) {
	last unless $pkg eq __PACKAGE__;
    }
    die "Cannot find calling package" unless $pkg;

    $self->lazy_load;
    foreach my $type (@$types) {
	no strict 'refs';
	my $method = $type;
	$method =~ s/::/_/g;
	$method =~ s/\*/__/g;
	next unless $type eq '*' or $self->is_type($type);

	unshift @_, $self;
	goto &{"$pkg\::$method"};
    }
}

sub callback_members {
    my $self = shift;
    while (my $member = $self->next_member) {
	$member->callback(@_);
    }
}

1;

__END__

=head1 AUTHORS

Autrijus Tang E<lt>autrijus@autrijus.orgE<gt>

=head1 COPYRIGHT

Copyright 2004 by Autrijus Tang E<lt>autrijus@autrijus.orgE<gt>.

This program is free software; you can redistribute it and/or modify it
under the same terms as Perl itself.

See L<http://www.perl.com/perl/misc/Artistic.html>

=cut
