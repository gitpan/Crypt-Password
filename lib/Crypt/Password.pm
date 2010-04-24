package Crypt::Password;
use Exporter 'import';
@EXPORT = ('password');
our $VERSION = "0.05";

use Carp;

use overload
    '""' => \&crypt,
    'eq' => \&crypt,
    'nomethod' => \&crypt;

# from libc6 crypt/crypt-entry.c
our %alg_to_magic = (
    md5 => '$1$',
    sha256 => '$5$',
    sha512 => '$6$',
);

our %magic_to_alg = reverse %alg_to_magic;

sub new {
    shift;
    password(@_);
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
    
    $self->{crypted} ||= $self->_crypt
}



sub input {
    my $self = shift;
    $self->{input} = shift;
    if ($self->_looks_crypted($self->{input})) {
        $self->{crypted} = delete $self->{input}
    }
}

sub salt {
    my $self = shift;
    my $provided = shift;
    if (defined $provided) {
        $self->{salt} = $provided
    }
    else {
        $self->{salt} ||= do {
            if ($self->{crypted}) {
                (split /\$/, $self->{crypted})[2]
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
        if (exists $alg_to_magic{lc $alg}) {
            $self->{algorithm_magic} = $alg_to_magic{lc $alg};
            $self->{algorithm} = lc $alg;
        }
        else {
            $self->{algorithm_magic} = $alg;
            $self->{algorithm} = $magic_to_alg{lc $alg};
        }
    }
    elsif (!$self->{algorithm}) {
        $self->algorithm($self->_default_algorithm)
    }
    else {
        $self->{algorithm}
    }
}

sub _crypt {
    my $self = shift;
    
    defined $self->{input} || croak "no input!";
    $self->{algorithm_magic} || croak "no algorithm!";
    defined $self->{salt} || croak "invalid salt!";
    
    CORE::crypt(delete $self->{input}, $self->{algorithm_magic}.$self->{salt})
}

sub check {
    my $self = shift;
    my $plaintext = shift;
    
    CORE::crypt($plaintext, $self) eq "$self";
}



our @valid_salt = ( "a".."z", "A".."Z", "0".."9", qw(/ \ ! @ % ^), "#" );

sub _invent_salt {
    join "", map { $valid_salt[rand(@valid_salt)] } 1..8;
}

sub _looks_crypted {
    my $self = shift;
    my $string = shift;
    $string && $string =~ m{^\$\d+\$.*\$.+$}
}

sub _default_algorithm {
    "sha256"
}

1;

__END__

=head1 NAME

Crypt::Password - Unix-style, Variously Hashed Passwords

=head1 SYNOPSIS

 use Crypt::Password;
 
 my $hashed = password("password");
 
 $user->set_password($hashed);
 
 if ($user->get_password eq password($from_client)) {
     # authenticated
 }
 
 # This is called Modular Crypt Format.
 
 if (password($from_database)->check($from_user)) {
     # authenticated
 }
 
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
usually (see L<KNOWN ISSUES>) in Modular Crypt Format:

 # scalar($hashed):
 #    v digest   v hash ->
 #   $5$%RK2BU%L$aFZd1/4Gpko/sJZ8Oh.ZHg9UvxCjkH1YYoLZI6tw7K8
 #      ^ salt ^

That you can store, etc, retrieve then give it to C<password()> again to
C<-E<gt>check($given_password)> or string compare to the output of a new
C<password($given_password)>.

If the given string is already hashed it is assumed to be okay to use it as is.
This means users can supply pre-hashed passwords to you.

=head1 FUNCTIONS

=over

=item password ( $password [, $salt [, $algorithm]] )

Constructs a Crypt::Password object.

=back

=head1 METHODS

=over

=item check ( $another_password )

Checks the given password hashes the same as that this object represents.

=item hash

Returns the hash.

=item salt

Returns the salt.

=item algorithm

Returns the algorithm by name.

=item algorithm_arg

Returns the algorithm as it is represented in the Modular Crypt Formatted
output of C<crypt(3)>.

=back

=head1 KNOWN ISSUES

Cryptographic functionality depends greatly on your local glibc's B<crypt(3)>.
Old Linux may not support sha*, many other platforms only support md5, or that
and Blowfish, etc.

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

