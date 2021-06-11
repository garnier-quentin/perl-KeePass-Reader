package KeePass::Keys::Composite;

use strict;
use warnings;
use KeePass::constants qw(:all);
use KeePass::Keys::Password;
use KeePass::Keys::File;
use Crypt::Digest::SHA256;

sub new {
    my ($class, %options) = @_;
    my $self  = {};
    bless $self, $class;

    $self->{keys} = [];
    return $self;
}

sub add_key_password {
    my ($self, %options) = @_;

    my $key_password = KeePass::Keys::Password->new();
    $key_password->set_password(password => $options{password});
    push @{$self->{keys}}, $key_password;
    return 0;
}

sub add_key_file {
    my ($self, %options) = @_;

    return (1, 'unsupported');
}

sub raw_key {
    my ($self, %options) = @_;

    my $raw_keys = '';
    foreach my $key (@{$self->{keys}}) {
        $raw_keys .= $key->raw_key();
    }

    if (defined($options{seed})) {
        # unsupported challenge
    }

    return Crypt::Digest::SHA256::sha256($raw_keys);
}

sub transform {
    my ($self, %options) = @_;

    my $raw_keys = $self->raw_key(seed => $options{kdf}->seed());
    return $options{kdf}->transform(raw_key => $raw_keys);
}

1;
