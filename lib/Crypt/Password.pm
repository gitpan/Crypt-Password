package Crypt::Password;
use Exporter 'import';
@EXPORT = ('password', 'crypt_password');
our $VERSION = "0.15";

use Carp;

use overload
    '""' => \&crypt,
    'eq' => \&crypt,
    'nomethod' => \&crypt;

# from libc6 crypt/crypt-entry.c
our %alg_to_id = (
    md5 => '1',
    blowfish => '2a',
    sha256 => '5',
    sha512 => '6',
);
our %id_to_alg = reverse %alg_to_id;

# switches off embodying crypted-looking passwords
our $definitely_crypt;

our $crypt_flav = do {
    $^O =~ /^MSWin/ ? 'windows' : do {
    $_ = (`man crypt`)[-1];
    /DragonFly/ ? 'dragonfly' :
    /NetBSD/ ? 'netbsd' :
    /OpenBSD/ ? 'openbsd' :
    /FreeBSD/ ? 'freebsd' :
    /FreeSec/ ? 'freesec' :
                'glib'
    }
};
our $flav_dispatch = {
    glib => {
        looks_crypted => sub {
            return $_[0] =~ m{^\$.+\$.*\$.+$}
        },
        salt_provided => sub {
            return shift;
        },
        extract_salt => sub {
            return (split /\$/, $_[0])[2]
        },
        format_crypted => sub {
            return shift;
        },
        form_salt => sub {
            my ($s, $self) = @_;
            if ($self->{algorithm_id}) {
                $s = sprintf('$%s$%s', $self->{algorithm_id}, $s);
            }
            else {
                # ->check(), alg and salt from ourselves, the rest be ignored
                $s = "$self";
            }
            return $s;
        },
        default_algorithm => sub {
            return "sha256";
        },
    },
    freesec => {
        looks_crypted => sub {
            # with our dollar-signs added in around the salt
            return $_[0] =~ /^\$(_.{8}|.{2})\$ (.{11})?$/x
        },
        salt_provided => sub {
            my $provided = shift;
            # salt must be 2 or 8 or entropy leaks in around the side
            # I am serious
            if ($provided =~    m/^\$(_.{8}|_?.{2})\$(.{11})?$/
                || $provided =~ m/^  (_.{8}|_?.{2})  (.{11})?$/x) {
                $provided = $1;
            }
            if ($provided =~ /^_..?$/) {
                croak "Bad salt input:"
                    ." 2-character salt cannot start with _";
            }
            $provided =~ s/^_//;
            if ($provided !~ m/^(.{8}|.{2})$/) {
                croak "Bad salt input:"
                    ." salt must be 2 or 8 characters long";
            }
            return $provided;
        },
        extract_salt => sub {
            $_[0] =~ /^\$(_.{8}|.{2})\$ (.{11})?$/x;
            my $s = $1;
            $s || croak "Bad crypted input:"
                    ." salt must be 2 or 8 characters long";
            $s =~ s/^_//;
            return $s
        },
        format_crypted => sub {
            my $crypt = shift;
            # makes pretty ambiguous crypt strings, lets add some dollar signs
            $crypt =~ s/^(_.{8}|..)(.{11})$/\$$1\$$2/
                || croak "failed to understand FreeSec crypt: '$crypt'";
            return $crypt;
        },
        form_salt => sub {
            my ($s) = @_;
            if (length($s) == 8) {
                $s = "_$s"
            }
            return $s;
        },
        default_algorithm => sub {
            return "DES" # does nothing
        },
    },
    freebsd => {
        base => "glib",
        default_algorithm => sub {
            return "2"
        },
        format_crypted => sub {
            my ($crypted, $salt) = (shift, pop);
            if ($_[-1] =~ m/^\$.+\$(.+)$/) {
                my $salt = $1;
                # put the salt in there
                $crypted =~ s/^\$(\d)/\$$1\$$salt\$/;
            }
            else {
                # makes pretty ambiguous crypt strings, lets add some dollar signs
                $crypted =~ s/^(_.{8}|..)(.{11})$/\$$1\$$2/
                    || croak "failed to understand Extended-format freebsd crypt: '$crypted'";
                # TODO if user passes underscorey salt they might want it plain Extended?
            }
            return $crypted;
        },
        looks_crypted => sub {
            # with our dollar-signs added in around the salt
            return $_[0] =~ /^\$(_.{8}|.{2})\$ (.{11})?$/x
                || $_[0] =~ m{^\$.+\$.*\$.+$}
        },
        extract_salt => sub {
            $_[0] =~ /^\$(_.{8}|.{2})\$ (.{11})?$/x;
            my $s = $1;
            $s || croak "Bad crypted input:"
                    ." salt must be 2 or 8 characters long";
            $s =~ s/^_//;
            return $s
        },
    },
    netbsd => {
        base => "freebsd",
    },
    openbsd => {
        base => "freebsd",
    },
    dragonfly => {
        base => "freebsd",
    },
    windows => {
        base => "freesec",
    },
};

sub flav {
    my $func = shift;
    my $flav = $flav_dispatch->{$crypt_flav} || die;
    unless (exists $flav->{$func}) {
        if (exists $flav->{base}) {
            local $crypt_flav = $flav->{base};
            return flav($func, @_);
        }
        die "no $func handler for (crypt flavour: $crypt_flav)";
    }
    return $flav->{$func}->(@_);
}

sub new {
    shift;
    password(@_);
}

sub crypt_password {
    local $definitely_crypt = 1;
    return password(@_);
}

sub password {
    my $self = bless {}, __PACKAGE__;

    $self->input(shift);
    
    unless ($self->{crypted}) {
        $self->salt(shift);
        
        $self->algorithm(shift); 
        
        $self->crypt();
    }

    $self
}

sub crypt {
    my $self = shift;
    
    $self->{crypted} ||= $self->_crypt;

    return "$self->{crypted}";
}

sub input {
    my $self = shift;
    $self->{input} = shift;
    if (!$definitely_crypt && $self->_looks_crypted($self->{input})) {
        $self->{crypted} = delete $self->{input}
    }
}

sub _looks_crypted {
    my $self = shift;
    my $string = shift || return;

    return flav(looks_crypted => $string);
}

sub salt {
    my $self = shift;
    my $provided = shift;
    if (defined $provided) {
        $self->{salt} = flav(salt_provided => $provided);
    }
    else {
        return $self->{salt} if defined $self->{salt};
        return $self->{salt} = do {
            if ($self->{crypted}) {
                return flav(extract_salt => $self->{crypted});
            }
            else {
                $self->_invent_salt()
            }
        };
    }
}

sub algorithm {
    my $self = shift;
    $alg = shift;
    if ($alg) {
        $alg =~ s/^\$?(.+)\$?$/$1/;
        if (exists $alg_to_id{lc $alg}) {
            $self->{algorithm_id} = $alg_to_id{lc $alg};
            $self->{algorithm} = lc $alg;
        }
        else {
            # $alg will be passed anyway, it may not be known to %id_to_alg
            $self->{algorithm_id} = $alg;
            $self->{algorithm} = $id_to_alg{lc $alg};
        }
    }
    elsif (!$self->{algorithm}) {
        $self->algorithm(flav("default_algorithm"));
    }
    else {
        $self->{algorithm}
    }
}

sub _crypt {
    my $self = shift;
    
    defined $self->{input} || croak "no input!";
    $self->{algorithm_id} || croak "no algorithm!";
    defined $self->{salt} || croak "invalid salt!";

    my $input = delete $self->{input};
    my $salt = $self->_form_salt();

    return _do_crypt($input, $salt);
}

sub check {
    my $self = shift;
    my $plaintext = shift;
   
    my $salt = $self->_form_salt();
    my $new = _do_crypt($plaintext, $salt);
    return $new eq "$self";
}

sub _do_crypt {
    my ($input, $salt) = @_;
    my $crypt = CORE::crypt($input, $salt);
    warn "# $input $salt = $crypt\n";
    $crypt = flav(format_crypted => $crypt, $input, $salt);
    return $crypt;
}

sub _form_salt {
    my $self = shift;
    my $s = $self->salt;
    croak "undef salt!?" unless defined $s;
    return flav(form_salt => $s, $self);
}

our @valid_salt = ( "/", ".", "a".."z", "A".."Z", "0".."9" );

sub _invent_salt {
    my $many = $_[1] || 8;
    join "", map { $valid_salt[rand(@valid_salt)] } 1..$many;
}

1;

__END__

=head1 NAME

Crypt::Password - Unix-style, Variously Hashed Passwords

=head1 SYNOPSIS

 use Crypt::Password;
 
 my $hashed = password("newpassword");
 
 $user->set_password($hashed);
 
 if (password($from_database)->check($password_from_user)) {
     # authenticated
 }

 my $definitely_crypted_just_then = crypt_password($maybe_already_crypted);

 # you also might want to
 password($a) eq password($b)
 # WARNING: password() will embody but not crypt an already crypted string.
 #          if you are checking something from the outside world, use check()

 # imagine stealing a crypted string and using it as a password. it happens.

 # WARNING: the following applies to glibc's crypt() only
 #          Non-Linux systems beware.

 # Default algorithm, supplied salt:
 my $hashed = password("password", "salt");
 
 # md5, no salt:
 my $hashed = password("password", "", "md5");
 
 # sha512, invented salt: 
 my $hashed = password("password", undef, "sha512");

=head1 DESCRIPTION

This is just a wrapper for perl's C<crypt()>, which can do everything you would
probably want to do to store a password, but this is to make usage easier.
The object stringifies to the return string of the crypt() function, which is
(B<on Linux/glibc>) in Modular Crypt Format:

 # scalar($hashed):
 #    v digest   v hash ->
 #   $5$%RK2BU%L$aFZd1/4Gpko/sJZ8Oh.ZHg9UvxCjkH1YYoLZI6tw7K8
 #      ^ salt ^

That you can store, etc, retrieve then give it to C<password()> again to
C<-E<gt>check($given_password)>.

Not without some danger, so read on, you could also string compare it to the
output of another C<password()>, as long as the salt is the same. Actually, if
you are running on B<Linux/glibc> you can pass the first password as the salt
to the second and it will get it right. Anyway, the danger:

If the given string is already hashed it is assumed to be okay to use it as is.
So if you are checking something from the outside world, C<-E<gt>check($it)>
against the thing you can trust. You could also use C<crypt_password()>, which
will definitely crypt its input.

This means simpler code and users can supply pre-hashed passwords initially, but
if you do it wrong a stolen hash could be used as a password, so buck up your ideas.

If you aren't running B<Linux/glibc>, everything after the WARNING in the synopsis
is dubious as. If you've got insight into how this module can work better on
B<Darwin/FreeSec> I would love to hear from you.

=head1 FUNCTIONS

=over

=item password ( $password [, $salt [, $algorithm]] )

Constructs a Crypt::Password object.

=item crypt_password ( $password [, $salt [, $algorithm]] )

Same as above but will definitely crypt $password, even if it looks crypted.
See warning labels.

=back

=head1 METHODS

=over

=item check ( $another_password )

Checks the given password hashes the same as that this object represents.

=item crypt

Returns the crypt string, same as stringifying the object.

=item salt

Returns the salt.

=back

=head1 KNOWN ISSUES

Cryptographic functionality depends greatly on your local B<crypt(3)>.
Old Linux may not support sha*, many other platforms only support md5, or that
and Blowfish, etc. You are likely fine.

On FreeSec's crypt, the crypted format is much different. Firstly, salt strings
must be either two or eight characters long, in the latter case they will be
prepended with an underscore for you. In the string you get back we also put the
salt between two dollar signs, to make it slightly less ambiguous, less likely
for C<password()> to assume something is crypted when it is not...

=head1 SUPPORT, SOURCE

If you have a problem, submit a test case via a fork of the github repo.

 http://github.com/st3vil/Crypt-Password

=head1 AUTHOR AND LICENCE

Code by Steve Eirium, L<nostrasteve@gmail.com>, idea by Sam Vilain,
L<sam.vilain@catalyst.net.nz>.  Development commissioned by NZ
Registry Services.

Copyright 2009, NZ Registry Services.  This module is licensed under
the Artistic License v2.0, which permits relicensing under other Free
Software licenses.

=head1 SEE ALSO

L<Digest::SHA>, L<Authen::Passphrase>, L<Crypt::SaltedHash>

=cut

