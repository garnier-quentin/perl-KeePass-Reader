#!/usr/bin/perl

use strict;
use warnings;
use FindBin;
use lib "$FindBin::Bin";
use KeePass::Reader;

my $keepass = KeePass::Reader->new();
$keepass->load_db(file => './files/testv4.kdbx', password => 'centreon');
my $error = $keepass->error();
if (defined($error)) {
    print "error: $error\n";
}
exit(0);
