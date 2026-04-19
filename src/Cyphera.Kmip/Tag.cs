// Copyright 2026 Horizon Digital Engineering LLC
// Licensed under the Apache License, Version 2.0

namespace Cyphera.Kmip;

/// <summary>
/// KMIP 1.4 tag, type, and enum constants.
///
/// Reference: OASIS KMIP Specification v1.4
/// https://docs.oasis-open.org/kmip/spec/v1.4/kmip-spec-v1.4.html
/// </summary>
public static class Tag
{
    // Message structure
    public const uint RequestMessage       = 0x420078;
    public const uint ResponseMessage      = 0x42007B;
    public const uint RequestHeader        = 0x420077;
    public const uint ResponseHeader       = 0x42007A;
    public const uint ProtocolVersion      = 0x420069;
    public const uint ProtocolVersionMajor = 0x42006A;
    public const uint ProtocolVersionMinor = 0x42006B;
    public const uint BatchCount           = 0x42000D;
    public const uint BatchItem            = 0x42000F;
    public const uint Operation            = 0x42005C;
    public const uint RequestPayload       = 0x420079;
    public const uint ResponsePayload      = 0x42007C;
    public const uint ResultStatus         = 0x42007F;
    public const uint ResultReason         = 0x420080;
    public const uint ResultMessage        = 0x420081;

    // Object identification
    public const uint UniqueIdentifier     = 0x420094;
    public const uint ObjectType           = 0x420057;

    // Naming
    public const uint Name                 = 0x420053;
    public const uint NameValue            = 0x420055;
    public const uint NameType             = 0x420054;

    // Attributes (KMIP 1.x style)
    public const uint Attribute            = 0x420008;
    public const uint AttributeName        = 0x42000A;
    public const uint AttributeValue       = 0x42000B;

    // Key structure
    public const uint SymmetricKey         = 0x42008F;
    public const uint KeyBlock             = 0x420040;
    public const uint KeyFormatType        = 0x420042;
    public const uint KeyValue             = 0x420045;
    public const uint KeyMaterial          = 0x420043;

    // Crypto attributes
    public const uint CryptographicAlgorithm = 0x420028;
    public const uint CryptographicLength    = 0x42002A;
    public const uint CryptographicUsageMask = 0x42002C;

    // Template
    public const uint TemplateAttribute    = 0x420091;

    // Key pair
    public const uint PrivateKeyUniqueIdentifier = 0x420066;
    public const uint PublicKeyUniqueIdentifier   = 0x42006F;
    public const uint PublicKey                   = 0x42004E;
    public const uint PrivateKey                  = 0x42004D;

    // Certificate
    public const uint Certificate      = 0x420021;
    public const uint CertificateType  = 0x42001D;
    public const uint CertificateValue = 0x42001E;

    // Crypto operations
    public const uint Data              = 0x420033;
    public const uint IVCounterNonce    = 0x420047;
    public const uint SignatureData     = 0x42004F;
    public const uint MACData           = 0x420051;
    public const uint ValidityIndicator = 0x420098;

    // Revocation
    public const uint RevocationReason     = 0x420082;
    public const uint RevocationReasonCode = 0x420083;

    // Query
    public const uint QueryFunction = 0x420074;

    // State
    public const uint State = 0x42008D;

    // Derivation
    public const uint DerivationMethod     = 0x420031;
    public const uint DerivationParameters = 0x420032;
    public const uint DerivationData       = 0x420030;

    // Lease
    public const uint LeaseTime = 0x420049;
}

/// <summary>KMIP operation codes (all 27 KMIP 1.4 operations).</summary>
public static class KmipOperation
{
    public const uint Create           = 0x00000001;
    public const uint CreateKeyPair    = 0x00000002;
    public const uint Register         = 0x00000003;
    public const uint ReKey            = 0x00000004;
    public const uint DeriveKey        = 0x00000005;
    public const uint Locate           = 0x00000008;
    public const uint Check            = 0x00000009;
    public const uint Get              = 0x0000000A;
    public const uint GetAttributes    = 0x0000000B;
    public const uint GetAttributeList = 0x0000000C;
    public const uint AddAttribute     = 0x0000000D;
    public const uint ModifyAttribute  = 0x0000000E;
    public const uint DeleteAttribute  = 0x0000000F;
    public const uint ObtainLease      = 0x00000010;
    public const uint Activate         = 0x00000012;
    public const uint Revoke           = 0x00000013;
    public const uint Destroy          = 0x00000014;
    public const uint Archive          = 0x00000015;
    public const uint Recover          = 0x00000016;
    public const uint Query            = 0x00000018;
    public const uint Poll             = 0x0000001A;
    public const uint DiscoverVersions = 0x0000001E;
    public const uint Encrypt          = 0x0000001F;
    public const uint Decrypt          = 0x00000020;
    public const uint Sign             = 0x00000021;
    public const uint SignatureVerify  = 0x00000022;
    public const uint MAC              = 0x00000023;
}

/// <summary>KMIP object types.</summary>
public static class KmipObjectType
{
    public const uint Certificate  = 0x00000001;
    public const uint SymmetricKey = 0x00000002;
    public const uint PublicKey    = 0x00000003;
    public const uint PrivateKey   = 0x00000004;
    public const uint SplitKey     = 0x00000005;
    public const uint Template     = 0x00000006;
    public const uint SecretData   = 0x00000007;
    public const uint OpaqueData   = 0x00000008;
}

/// <summary>KMIP result status codes.</summary>
public static class KmipResultStatus
{
    public const uint Success          = 0x00000000;
    public const uint OperationFailed  = 0x00000001;
    public const uint OperationPending = 0x00000002;
    public const uint OperationUndone  = 0x00000003;
}

/// <summary>KMIP key format types.</summary>
public static class KmipKeyFormatType
{
    public const uint Raw                  = 0x00000001;
    public const uint Opaque               = 0x00000002;
    public const uint Pkcs1                = 0x00000003;
    public const uint Pkcs8                = 0x00000004;
    public const uint X509                 = 0x00000005;
    public const uint EcPrivateKey         = 0x00000006;
    public const uint TransparentSymmetric = 0x00000007;
}

/// <summary>Cryptographic algorithms.</summary>
public static class KmipAlgorithm
{
    public const uint Des        = 0x00000001;
    public const uint TripleDes  = 0x00000002;
    public const uint Aes        = 0x00000003;
    public const uint Rsa        = 0x00000004;
    public const uint Dsa        = 0x00000005;
    public const uint Ecdsa      = 0x00000006;
    public const uint HmacSha1   = 0x00000007;
    public const uint HmacSha224 = 0x00000008;
    public const uint HmacSha256 = 0x00000009;
    public const uint HmacSha384 = 0x0000000A;
    public const uint HmacSha512 = 0x0000000B;
    public const uint HmacMd5    = 0x0000000C;
}

/// <summary>KMIP name types.</summary>
public static class KmipNameType
{
    public const uint UninterpretedTextString = 0x00000001;
    public const uint Uri                     = 0x00000002;
}

/// <summary>Cryptographic usage mask (bitmask).</summary>
public static class KmipUsageMask
{
    public const uint Sign         = 0x00000001;
    public const uint Verify       = 0x00000002;
    public const uint Encrypt      = 0x00000004;
    public const uint Decrypt      = 0x00000008;
    public const uint WrapKey      = 0x00000010;
    public const uint UnwrapKey    = 0x00000020;
    public const uint Export       = 0x00000040;
    public const uint MacGenerate  = 0x00000080;
    public const uint MacVerify    = 0x00000100;
    public const uint DeriveKey    = 0x00000200;
    public const uint KeyAgreement = 0x00000800;
}
