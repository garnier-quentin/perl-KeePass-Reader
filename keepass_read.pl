#!/usr/bin/perl

use strict;
use warnings;
use FindBin;
use lib "$FindBin::Bin";
use Data::Dumper;
use KeePass::Reader;

my $keepass = KeePass::Reader->new();
my $content = $keepass->load_db(file => './files/testv4_3.kdbx', password => 'centreon');
my $error = $keepass->error();
if (defined($error)) {
    print "error: $error\n";
}
print Data::Dumper::Dumper($content);

exit(0);
