#!/usr/bin/perl
use strict;
use warnings;
use Test::More 'no_plan';

use FindBin '$Bin';
use lib "$Bin/../lib";
use_ok "Crypt::Password";

sub mock { bless {@_}, "Crypt::Password" };

no warnings 'once', 'redefine';
my $flav = $Crypt::Password::crypt_flav;
diag "testing Crypt::Password (crypt_flav='$flav')";
diag "os is '$^O'";
my $line = (`man crypt`)[-1];
$line =~ s/\s+/ /g;
diag "bottom line of man crypt: '$line'";

sub isnt {
    my ($a, $b, $c) = @_;
    Test::More::isnt("$a", "$b", $c);
}

if ($flav eq "glib") {
    glib();
}
elsif ($flav eq "freesec") {
    freesec();
}
else {
    other();
    diag "As if GLIB";
    $Crypt::Password::crypt_flav = "glib";
    glib();
    diag "As if freesec";
    $Crypt::Password::crypt_flav = "freesec";
    freesec();
}

sub glib {
#         _  _  _           
#        | |(_)| |          
#   __ _ | | _ | |__    ___ 
#  / _` || || || '_ \  / __|
# | (_| || || || |_) || (__ 
#  \__, ||_||_||_.__/  \___|
#   __/ |                   
#  |___/                    

    diag "set algorithm";
    my $c = mock;
    is $c->algorithm, "sha256", "default algorithm";
    is $c->{algorithm}, "sha256", "default algorithm";
    is $c->{algorithm_id}, '5', "default algorithm id";
    
    is $c->algorithm("sha512"), "sha512", "set algorithm (sha512)";
    is $c->{algorithm}, "sha512", "set algorithm (sha512)";
    is $c->{algorithm_id}, '6', "set algorithm id";
    
    is $c->algorithm, "sha512", "get algorithm";
    
    is $c->algorithm('1'), "md5", "set algorithm by id (md5)";
    is $c->{algorithm}, "md5", "correct set algorithm (sha512)";
    is $c->{algorithm_id}, '1', "correct set algorithm id";
    
    is $c->algorithm, "md5", "get algorithm";
    
    is $c->algorithm('3a'), undef, "set unknown id";
    is $c->{algorithm}, undef, "unknown id";
    is $c->{algorithm_id}, '3a', "id";


    diag "generate salt";
    $c = mock;
    my $salt_1 = $c->salt;
    like $salt_1, qr/^\S{8}$/, "salt generated";
    $c = mock;
    my $salt_2 = $c->salt;
    like $salt_1, qr/^\S{8}$/, "salt generated";
    isnt $salt_1, $salt_2, "generated salts are different";
    
    is $c->salt("4fatness"), "4fatness", "salt set, returned";
    is $c->{salt}, "4fatness", "salt set, returned";

    
    diag "crypt some text";
    
    $c = password("hello0");
    like $c, qr/^\$5\$(........)\$[a-zA-Z0-9\.\/]{43}$/, "crypted";
    
    my $c2 = password("hello0");
    like $c2, qr/^\$5\$(........)\$[a-zA-Z0-9\.\/]{43}$/, "another crypted";
    isnt "$c", "".$c2, "generated different salts";
    ok $c->check("hello0"), "validates";
    ok !$c->check("hello1"), "invalidates";
    
    my $c3 = password("hello0", $c->salt);
    is($c, $c3, "same salt");
    ok($c3->check("hello0"), "yes indeed");
    
    
    diag "documented stuff";
    {
        my $hashed = password("password", "salt");
        like $hashed, qr/^\$5\$salt\$.{43}$/, "Default algorithm, supplied salt";
    }

    {
        my $hashed = password("password", "", "md5");
        like $hashed, qr/^\$1\$\$.{22}$/, "md5, no salt";
    }

    {
        my $hashed = password("password", undef, "sha512");
        like $hashed, qr/^\$6\$(.{8})\$.{86}$/, "sha512, invented salt";
    }

    {
        my $password = '$5$%RK2BU%L$aFZd1/4Gpko/sJZ8Oh.ZHg9UvxCjkH1YYoLZI6tw7K8';
        is $password, password($password), "password embodied by password()";
        isnt "$password", "".crypt_password($password), "password recrypted by crypt_password()";

        # lately insane
        ok password($password) eq password($password), "comparison test";
        my $p1 = password($password);
        my $p2 = password($password);
        ok $p1 eq $p2, "comparison test";
    }
}
sub freesec {
# ______                    _____             
# |  ___|                  /  ___|            
# | |_    _ __   ___   ___ \ `--.   ___   ___ 
# |  _|  | '__| / _ \ / _ \ `--. \ / _ \ / __|
# | |    | |   |  __/|  __//\__/ /|  __/| (__ 
# \_|    |_|    \___| \___|\____/  \___| \___|

    my $c = password("hello0");
    like $c, qr/^\$_\S{8}\$\S{11}$/, "crypted: looks good";
    like password("hello0", "dg"), qr/^\$..\$\S{11}$/, "crypted: 2char supplied salt";

    diag "various salt inputs";
    # all invalid
    for my $salt ("dgdb", "a", "123456", "1234567", "123456789") {
        eval { password("hello0", $salt) };
        like $@, qr/Bad salt input.+2 or 8 characters/, "wrong sized salt";
        $@ = "";
    }
    for my $salt ("_a", "_bb") {
        eval { password("hello0", "_a") };
        like $@, qr/Bad salt input.+2-character salt cannot start with _/,
            "can't start with _";
        $@ = "";
    }

    # all valid
    my $p;
    eval { $p = password('a', 'bbbbbbbb') };
    is $@, "", "salt=8 no error";
    is $p, '$_bbbbbbbb$DJEHexiq9NI', "salt=8 crypt";
    undef $@;

    eval { $p = password('a', 'cc') };
    is $@, "", "salt=2 no error";
    is $p, '$cc$DFDkLhMbQ7wZ.', "salt=2 crypt";
    undef $@;

    diag "checks, comparisons";
    ok($c->check("hello0"), "check the correct password");
    ok(!$c->check("helow"), "check the wrong password");
    isnt($c, password("hello0", "ga"), "compare a password - wrong salt");
    isnt($c, password("hello0", "DADAdada"), "compare a password - wrong salt");
    isnt($c, password("hello0", "etcetcet"), "compare a password - wrong salt");
    is($c, password("hello0", $c->salt), "compare a password - correct salt");
    isnt($c, password("hello1", $c->salt), "wrong password");
    
    isnt(password("007", "blahblah"), password("007", "BLAHblah"), "compare a password - wrong salt");
    is(my $c2 = password("123", "12341234"), password("123", "12341234"), "compare a password - correct salt");
    ok($c2->check("123"), "check the correct password");
    ok(!$c2->check("12341234"), "check the wrong password");
    ok(!$c2->check($c2), "can't just pass crypted stuff into check()");
    ok(!$c2->check(password("123", $c2->salt)), "can't just pass crypted stuff into check()");

    diag "remake some known crypts";
    my @answers = map {[ split /\s+/, $_ ]} split /\n/, <<'ANSWERS';
ambiente $_12345555$V4oENXvTMYk $gi$CZewZaJV4pk
lampshade $_12345555$JacsOKd1xTo $gi$zi7R25ah3Zw
guitar $_12345555$2yFp.wqJEF. $gi$4tl8fx6Anh.
ANSWERS

    for my $row (@answers) {
        is(password($row->[0], "12345555"), $row->[1], "test $row->[0] salt=8");
        is(password($row->[0], "gi"), $row->[2], "test $row->[0] salt=2");
    }

    diag "reinstating a crypt object";
    my $c2_2 = password("$c2");
    is($c2, $c2_2, "stringified and back");
    is("$c2", "$c2_2", "stringified and back");
    ok($c2_2->check("123"), "stringified and back, check correct");
    ok(!$c2_2->check("23"), "stringified and back, check incorrect");
    ok($c2->check("123"), "123 still good");
    is($c2_2->salt, "12341234", "can extract the salt");
    ok(!password("$c2")->check('$_12341234$123'), "can't just pass crypted stuff into check()");
    my $crypted = '$_12345555$V4oENXvTMYk';
    is(password($crypted), $crypted, "crypted password embodied");
    isnt(crypt_password($crypted), $crypted, "crypted crypt_password recrypted");
}

sub other {
    diag "flav is $flav! how intriguing";

    do {
        local $Crypt::Password::crypt_flav = "glib";
        diag "algorithm: $_";
        diag "as glib: ". password('hello', '$'.$_.'$blah');
        diag "as glib: ". password('hello', '$'.$_.'$bl');
        local $Crypt::Password::crypt_flav = "freeseclax";
        diag "as freesec: ". password('hello', '_blah');
        diag "as freesec: ". password('hello', 'bl');
    } for 1..6;
    diag "simple usage: ".password('hello');
    diag "simple usage: ".password('hello');
    diag "simple usage: ".password('hello');
    diag "supplied salt 1: ".password('hello', '123');
    diag "supplied salt 1: ".password('hello', '123');
    diag "supplied salt 1: ".password('hello', '123');
    diag "supplied salt 1: ".password('hello', '123');
    diag "supplied salt 2: ".password('hello', '12345678');
    diag "supplied salt 2: ".password('hello', '12345678');
    diag "supplied salt 2: ".password('hello', '12345678');
    diag " o ".Crypt::Password::_do_crypt("blah", '$2a$blah');
    diag " o ".Crypt::Password::_do_crypt("blah", '$2a$blah');
    diag " o ".Crypt::Password::_do_crypt("blah", '$2a$blahblah');
    diag " o ".Crypt::Password::_do_crypt("blah", '$2a$blahblah');
    my $p = password("hello");
    diag "made $p";
    diag "check alright: ".($p->check("hello") ? "yes" : "no");
}

