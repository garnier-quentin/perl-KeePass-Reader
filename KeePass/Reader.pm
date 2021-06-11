package KeePass::Reader;

use strict;
use warnings;
use KeePass::constants qw(:all);
use POSIX;
use Data::UUID;
use Crypt::Digest::SHA256;
use Crypt::Digest::SHA512;
use Crypt::Mac::HMAC;
use Encode;
use KeePass::Crypto::Aes2Kdf;
use KeePass::Crypto::Argon2Kdf;
use KeePass::Keys::Composite;

sub new {
    my ($class, %options) = @_;
    my $self  = {};
    bless $self, $class;

    $self->{composite} = KeePass::Keys::Composite->new();
    $self->{uuid} = Data::UUID->new();
    return $self;
}

sub error {
    my ($self, %options) = @_;
    
    if (defined($options{message})) {
        $self->{error_msg} = $options{message};
    }

    return $self->{error_msg};
}

sub load_db {
    my ($self, %options) = @_;

    $self->{error_msg} = undef; 
    $self->{buffer_file} = undef; 
    $self->{master_read_pos} = 0;

    $self->{buffer_file} = $self->slurp(file => $options{file});
    return if (!defined($self->{buffer_file}));

    # there is also the composite key to manage
    return $self->read_database(password => $options{password});
}

sub read_database {
    my ($self, %options) = @_;

    return if ($self->read_magic_numbers());

    if ($self->{sig1} == KeePass1_Signature_1 && $self->{sig2} == KeePass1_Signature_2) {
        $self->error(message => "KeePass 1 database unsupported");
        return ;
    }
    if (!($self->{sig1} == KeePass2_Signature_1 && $self->{sig2} == KeePass2_Signature_2)) {
        $self->error(message => "Not a KeePass database");
        return ;
    }

    if ($self->{version} < KeePass2_File_Version_4) {
        $self->error(message => "Unsupported KeePass 2 database version (only version 4)");
        return ;
    }

    return if ($self->keepass4_read_header_fields());
    if (!defined($self->{m_master_seed}) || !defined($self->{m_encryption_iv}) || !defined($self->{cipher_mode})) {
        $self->error(message => 'missing database headers');
        return ;
    }

    my $header_sha256 = unpack('@' . $self->{master_read_pos} . ' a32', $self->{buffer_file});
    $self->{master_read_pos} += 32;
    my $header_hmac = unpack('@' . $self->{master_read_pos} . ' a32', $self->{buffer_file});
    $self->{master_read_pos} += 32;

    if (length($header_sha256) != 32 || length($header_hmac) != 32) {
        $self->error(message => 'Invalid header checksum size');
        return ;
    }
    my $header_sha256_hex = unpack('H*', $header_sha256);
    my $header_hmac_hex = unpack('H*', $header_hmac);
    my $header_data = unpack('a' . ($self->{end_header_pos}), $self->{buffer_file});
    my $header_data_sha256_hex = Crypt::Digest::SHA256::sha256_hex($header_data);

    if ($header_data_sha256_hex ne $header_sha256_hex) {
        $self->error(message => 'Header SHA256 mismatch');
        return ;
    }

    my ($ret, $message) = $self->{composite}->add_key_password(password => $options{password});
    if ($ret) {
        $self->error(message => $message);
        return ;
    }
    my $transformed_key = $self->{composite}->transform(kdf => $self->{kdf});

    my $hmac_key = Crypt::Digest::SHA512::sha512(
        pack('Q', 18446744073709551615) . Crypt::Digest::SHA512::sha512(
            $self->{m_master_seed} . $transformed_key . pack('C', 0x01)
        )
    );

    my $header_hmac_calc_hex = Crypt::Mac::HMAC::hmac_hex(
        'SHA256',
        $hmac_key,
        $header_data
    );
    if ($header_hmac_hex ne $header_hmac_calc_hex) {
        $self->error(message => 'Invalid credentials were provided or database file may be corrupt');
        return ;
    }

    print "===ici==\n";
}

sub read_magic_numbers {
    my ($self, %options) = @_;

    ($self->{sig1}, $self->{sig2}, $self->{version}) = unpack('VVV', $self->{buffer_file});
    if (!defined($self->{sig1}) || !defined($self->{sig2}) || !defined($self->{version})) {
        $self->error(message => "Failed to read database file");
        return 1;
    }

    $self->{master_read_pos} = 12;
    return 0;
}

sub keepass_set_chipher_id {
    my ($self, %options) = @_;

    if (length($options{field_data}) != Uuid_Length) {
        $self->error(message => "Invalid cipher uuid length:");
        return 1;
    }
    
    my $uuid = $self->{uuid}->to_string($options{field_data});
    if (!defined($uuid)) {
        $self->error(message => "Unable to parse UUID");
        return 1;
    }

    if ($uuid eq KeePass2_Cipher_Aes128) {
        $self->{cipher_mode} = Aes128_CBC;
    } elsif ($uuid eq KeePass2_Cipher_Aes256) {
        $self->{cipher_mode} = Aes256_CBC;
    } elsif ($uuid eq KeePass2_Cipher_Chacha20) {
        $self->{cipher_mode} = ChaCha20;
    } elsif ($uuid eq KeePass2_Cipher_Twofish) {
        $self->{cipher_mode} = Twofish_CBC;
    }

    if (!defined($self->{cipher_mode})) {
        $self->error(message => "Unsupported cipher");
        return 1;
    }

    return 0;
}

sub keepass_set_kdf {
    my ($self, %options) = @_;

    my $map = $self->keepass2_read_variant_map(field_data => $options{field_data});
    return 1 if (!defined($map));

    if (!defined($map->{'$UUID'}) || length($map->{'$UUID'}) != Uuid_Length) {
        $self->error(message => 'Unsupported key derivation function (KDF) or invalid parameters');
        return 1;
    }
    my $kdf_uuid = $self->{uuid}->to_string($map->{'$UUID'});
    if ($kdf_uuid eq KeePass2_Kdf_Aes_Kdbx3) {
        $kdf_uuid = KeePass2_Kdf_Aes_Kdbx4;
    }

    if ($kdf_uuid eq KeePass2_Kdf_Aes_Kdbx4) {
        $self->{kdf} = KeePass::Crypto::Aes2Kdf->new();
    } elsif ($kdf_uuid eq KeePass2_Kdf_Argon2D) {
        $self->{kdf} = KeePass::Crypto::Argon2Kdf->new(type => KeePass2_Kdf_Argon2D);
    } elsif ($kdf_uuid eq KeePass2_Kdf_Argon2Id) {
        $self->{kdf} = KeePass::Crypto::Argon2Kdf->new(type => KeePass2_Kdf_Argon2Id);
    } else {
        $self->error(message => 'Unsupported key derivation function (KDF) or invalid parameters');
        return 1;
    }

    if ($self->{kdf}->process_parameters(params => $map)) {
        $self->error(message => 'Unsupported key derivation function (KDF) or invalid parameters');
        return 1;
    }

    return 0;
}

sub keepass_set_compression_flags {
    my ($self, %options) = @_;

    if (length($options{field_data}) != 4) {
        $self->error(message => 'Invalid compression flags length');
        return 1;
    }

    my $id = unpack('V', $options{field_data});
    if ($id > CompressionAlgorithmMax) {
        $self->error(message => 'Unsupported compression algorithm');
        return 1;
    }

    $self->{compression_algorithm} = $id;
    return 0;
}

sub keepass4_read_header_fields {
    my ($self, %options) = @_;

    $self->{start_header_pos} = $self->{master_read_pos};

    $self->{compression_algorithm} = CompressionNone;
    $self->{header_comment} = undef;
    $self->{m_encryption_iv} = undef;
    $self->{m_master_seed} = undef;
    $self->{cipher_mode} = undef;
    while (1) {
        my ($field_id, $field_len) = unpack('@' . $self->{master_read_pos} . ' CV', $self->{buffer_file});
        if (!defined($field_id)) {
            $self->error(message => "Invalid header id size");
            return 1;
        }
        if (!defined($field_len)) {
            $self->error(message => "Invalid header field length");
            return 1;
        }
        $self->{master_read_pos} += 5;
        
        my $field_data;
        if ($field_len > 0) {
            $field_data = unpack('@' . $self->{master_read_pos} . ' a' . $field_len, $self->{buffer_file});
            if (!defined($field_data) || length($field_data) != $field_len) {
                $self->error(message => "Invalid header data length");
                return 1;
            }

            $self->{master_read_pos} += $field_len;
        }

        if ($field_id == KeePass2_HeaderFieldID_EndOfHeader) {
            last;
        } elsif ($field_id == KeePass2_HeaderFieldID_Comment) {
            
        } elsif ($field_id == KeePass2_HeaderFieldID_CipherID) {
            return 1 if ($self->keepass_set_chipher_id(field_data => $field_data));
        } elsif ($field_id == KeePass2_HeaderFieldID_CompressionFlags) {
            return 1 if ($self->keepass_set_compression_flags(field_data => $field_data));
        } elsif ($field_id == KeePass2_HeaderFieldID_EncryptionIV) {
             $self->{m_encryption_iv} = $field_data;
        } elsif ($field_id == KeePass2_HeaderFieldID_MasterSeed) {
            if (length($field_data) != 32) {
                $self->error(message => "Invalid master seed size");
                return 1;
            }
            $self->{m_master_seed} = $field_data;
        } elsif ($field_id == KeePass2_HeaderFieldID_KdfParameters) {
            return 1 if ($self->keepass_set_kdf(field_data => $field_data));
        } elsif ($field_id == KeePass2_HeaderFieldID_PublicCustomData) {
            
        } elsif (
            $field_id == KeePass2_HeaderFieldID_ProtectedStreamKey ||
            $field_id == KeePass2_HeaderFieldID_TransformRounds ||
            $field_id == KeePass2_HeaderFieldID_TransformSeed ||
            $field_id == KeePass2_HeaderFieldID_StreamStartBytes ||
            $field_id == KeePass2_HeaderFieldID_InnerRandomStreamID
        ) {
            $self->error(message => "Legacy header fields found in KDBX4 file");
            return 1; 
        }

        
    }

    $self->{end_header_pos} = $self->{master_read_pos};
    return 0;
}

sub keepass2_read_variant_map {
    my ($self, %options) = @_;

    my $map = {};
    my $pos = 0;
    my $version = unpack('v', $options{field_data});
    my $max_version = VariantMap_Version & VariantMap_Critical_Mask;
    if (!defined($version) || ($version > $max_version)) {
        $self->error(message => "Unsupported KeePass variant map version");
        return undef;
    }
    $pos += 2;
    while (1) {
        my $field_type = ord(unpack('@' . $pos . ' a', $options{field_data}));
        $pos++;
        if (!defined($field_type)) {
            $self->error(message => 'Invalid variant map field type size');
            return undef;
        }
        if ($field_type == VariantMapFieldType_End) {
            last;
        }
        
        my $name_len = unpack('@' . $pos . ' V', $options{field_data});
        $pos += 4;
        if (!defined($name_len)) {
            $self->error(message => 'Invalid variant map entry name length');
            return undef;
        }
        
        my $name_data = unpack('@' . $pos . ' a' . $name_len, $options{field_data});
        $pos += $name_len;
        if (!defined($name_data) || length($name_data) != $name_len) {
            $self->error(message => 'Invalid variant map entry name data');
            return undef;
        }
        $name_data = Encode::decode('UTF-8', $name_data);

        my $value_len = unpack('@' . $pos . ' V', $options{field_data});
        $pos += 4;
        if (!defined($value_len)) {
            $self->error(message => 'Invalid variant map entry value length');
            return undef;
        }
        
        my $value_data = unpack('@' . $pos . ' a' . $value_len, $options{field_data});
        $pos += $value_len;
        if (!defined($value_data) || length($value_data) != $value_len) {
            $self->error(message => 'Invalid variant map entry value data');
            return undef;
        }

        if ($field_type == VariantMapFieldType_UInt64) {
            $map->{$name_data} = unpack('Q', $value_data);
        } elsif ($field_type == VariantMapFieldType_UInt32) {
            $map->{$name_data} = unpack('V', $value_data);
        } elsif ($field_type == VariantMapFieldType_Int32) {
            $map->{$name_data} = unpack('l', $value_data);
        } elsif ($field_type == VariantMapFieldType_Int64) {
            $map->{$name_data} = unpack('q', $value_data);
        } elsif ($field_type == VariantMapFieldType_String) {
            $map->{$name_data} = Encode::decode('UTF-8', $value_data);
        } elsif ($field_type == VariantMapFieldType_ByteArray) {
            $map->{$name_data} = $value_data;
        } else {
            $self->error(message => 'Invalid variant map entry type');
            return undef;
        }
    }

    return $map;
}

sub slurp {
    my ($self, %options) = @_;

    my ($fh, $size);
    if (!open($fh, '<', $options{file})) {
        $self->error(message => "Could not open $options{file}: $!");
        return undef;
    }
    if (!($size = -s $options{file})) {
        $self->error(message => "File $options{file} appears to be empty");
        return undef;
    }
    binmode $fh;
    read($fh, my $buffer, $size);
    close $fh;
    if (length($buffer) != $size) {
        $self->error(message => "Could not read entire file contents of $options{file}");
        return undef;
    }
    return $buffer;
}

1;
