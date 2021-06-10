package KeePass::constants;

use strict;
use warnings;
use base qw(Exporter);

my %constants;
BEGIN {
    %constants = (
        KeePass1_Signature_1 => 0x9AA2D903,
        KeePass1_Signature_2 => 0xB54BFB65,

        KeePass2_Signature_1 => 0x9AA2D903,
        KeePass2_Signature_2 => 0xB54BFB67,
        KeePass2_File_Version_4 => 0x00040000,
        KeePass2_File_Version_3_1 => 0x00030001,
        KeePass2_File_Version_3 => 0x00030000,
        KeePass2_File_Version_2 => 0x00020000,

        KeePass2_HeaderFieldID_EndOfHeader => 0,
        KeePass2_HeaderFieldID_Comment => 1,
        KeePass2_HeaderFieldID_CipherID => 2,
        KeePass2_HeaderFieldID_CompressionFlags => 3,
        KeePass2_HeaderFieldID_MasterSeed => 4,
        KeePass2_HeaderFieldID_TransformSeed => 5,
        KeePass2_HeaderFieldID_TransformRounds => 6,
        KeePass2_HeaderFieldID_EncryptionIV => 7,
        KeePass2_HeaderFieldID_ProtectedStreamKey => 8,
        KeePass2_HeaderFieldID_StreamStartBytes => 9,
        KeePass2_HeaderFieldID_InnerRandomStreamID => 10,
        KeePass2_HeaderFieldID_KdfParameters => 11,
        KeePass2_HeaderFieldID_PublicCustomData => 12,

        Uuid_Length => 16,

        KeePass2_Cipher_Aes128 => '61ab05a1-9464-41c3-8d74-3a563df8dd35',
        KeePass2_Cipher_Aes256 => '31c1f2e6-bf71-4350-be58-05216afc5aff',
        KeePass2_Cipher_Twofish => 'ad68f29f-576f-4bb9-a36a-d47af965346c',
        KeePass2_Cipher_Chacha20 => 'd6038a2b-8b6f-4cb5-a524-339a31dbb59a',

        KeePass2_Kdf_Aes_Kdbx3 => 'c9d9f39a-628a-4460-bf74-0d08c18a4fea',
        KeePass2_Kdf_Aes_Kdbx4 => '7c02bb82-79a7-4ac0-927d-114a00648238',
        KeePass2_Kdf_Argon2D => 'ef636ddf-8c29-444b-91f7-a9a403e30a0c',
        KeePass2_Kdf_Argon2Id => '9e298b19-56db-4773-b23d-fc3ec6f0a1e6',

        Aes128_CBC => 1,
        Aes256_CBC => 2,
        ChaCha20 => 3,
        Twofish_CBC => 4,

        VariantMap_Version => 0x0100,
        VariantMap_Critical_Mask => 0xFF00,

        VariantMapFieldType_End => 0,
        VariantMapFieldType_Byte => 2, #0x02,
        VariantMapFieldType_UInt16 => 3, #0x03,
        VariantMapFieldType_UInt32 => 4, #0x04,
        VariantMapFieldType_UInt64 => 5, #0x05,
        VariantMapFieldType_SByte => 10, #0x0A,
        VariantMapFieldType_Int16 => 11, #0x0B,
        VariantMapFieldType_Int32 => 12, #0x0C,
        VariantMapFieldType_Int64 => 13, #0x0D,
        VariantMapFieldType_Float => 16, #0x10,
        VariantMapFieldType_Double => 17, #0x11,
        VariantMapFieldType_Decimal => 18, #0x12,
        VariantMapFieldType_Char => 23, #0x17,
        VariantMapFieldType_String => 24, #0x18,
        VariantMapFieldType_ByteArray => 66, #0x42

        KdfParam_Aes_Rounds => 'R',
        KdfParam_Aes_Seed => 'S',
        KdfParam_Argon2_Salt => 'S',
        KdfParam_Argon2_Parallelism => 'P',
        KdfParam_Argon2_Memory => 'M',
        KdfParam_Argon2_Iterations => 'I',
        KdfParam_Argon2_Version => 'V',
        KdfParam_Argon2_Secret => 'K',
        KdfParam_Argon2_Assocdata => 'A',

        Kdf_Min_Seed_Size => 8,
        Kdf_Max_Seed_Size => 32
    );
}

use constant \%constants;
our @EXPORT;
our @EXPORT_OK = keys %constants;

our %EXPORT_TAGS = ( all => [ @EXPORT_OK ] );

1;
