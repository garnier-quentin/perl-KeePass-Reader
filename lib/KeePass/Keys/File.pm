package KeePass::Keys::File;

use strict;
use warnings;
use KeePass::constants qw(:all);

sub new {
    my ($class, %options) = @_;
    my $self  = {};
    bless $self, $class;

    return $self;
}

1;
