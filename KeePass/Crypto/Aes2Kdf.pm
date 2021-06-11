package KeePass::Crypto::Aes2Kdf;

use strict;
use warnings;
use POSIX;
use KeePass::constants qw(:all);

sub new {
    my ($class, %options) = @_;
    my $self  = {};
    bless $self, $class;

    return $self;
}

sub seed {
    my ($self, %options) = @_;

    return $self->{m_seed};
}

sub process_parameters {
    my ($self, %options) = @_;

    $self->{m_seed} = $options{params}->{&KdfParam_Aes_Seed};
    if (!defined($self->{m_seed}) || length($self->{m_seed}) < Kdf_Min_Seed_Size || length($self->{m_seed}) > Kdf_Max_Seed_Size) {
        return 1;
    }

    $self->{m_rounds} = $options{params}->{&KDFPARAM_AES_ROUNDS};
    if (!defined($self->{m_rounds}) || $self->{m_rounds} < 1 || $self->{m_rounds} > POSIX::INT_MAX) {
        return 1;
    }
    
    return 0;
}

1;
