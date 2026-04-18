// Copyright 2026 Horizon Digital Engineering LLC
// Licensed under the Apache License, Version 2.0

using System.Reflection;
using Cyphera.Kmip;
using Xunit;

namespace Cyphera.Kmip.Tests;

/// <summary>Helper to extract constant values via reflection.</summary>
internal static class ConstantHelper
{
    public static List<uint> GetUIntConstants(Type type)
    {
        return type.GetFields(BindingFlags.Public | BindingFlags.Static)
            .Where(f => f.IsLiteral && !f.IsInitOnly && f.FieldType == typeof(uint))
            .Select(f => (uint)f.GetValue(null)!)
            .ToList();
    }
}

// ---------------------------------------------------------------------------
// ObjectType values -- KMIP 1.4 Section 9.1.3.2.3
// ---------------------------------------------------------------------------

public class ObjectTypeTests
{
    [Fact] public void Certificate()  => Assert.Equal(0x00000001u, KmipObjectType.Certificate);
    [Fact] public void SymmetricKey() => Assert.Equal(0x00000002u, KmipObjectType.SymmetricKey);
    [Fact] public void PublicKey()    => Assert.Equal(0x00000003u, KmipObjectType.PublicKey);
    [Fact] public void PrivateKey()   => Assert.Equal(0x00000004u, KmipObjectType.PrivateKey);
    [Fact] public void SplitKey()     => Assert.Equal(0x00000005u, KmipObjectType.SplitKey);
    [Fact] public void Template()     => Assert.Equal(0x00000006u, KmipObjectType.Template);
    [Fact] public void SecretData()   => Assert.Equal(0x00000007u, KmipObjectType.SecretData);
    [Fact] public void OpaqueData()   => Assert.Equal(0x00000008u, KmipObjectType.OpaqueData);

    [Fact]
    public void NoDuplicateValues()
    {
        var values = ConstantHelper.GetUIntConstants(typeof(KmipObjectType));
        Assert.Equal(values.Count, new HashSet<uint>(values).Count);
    }
}

// ---------------------------------------------------------------------------
// Operation values -- KMIP 1.4 Section 9.1.3.2.2
// ---------------------------------------------------------------------------

public class OperationTests
{
    [Fact] public void Create()   => Assert.Equal(0x00000001u, KmipOperation.Create);
    [Fact] public void Locate()   => Assert.Equal(0x00000008u, KmipOperation.Locate);
    [Fact] public void Get()      => Assert.Equal(0x0000000Au, KmipOperation.Get);
    [Fact] public void Activate() => Assert.Equal(0x00000012u, KmipOperation.Activate);
    [Fact] public void Destroy()  => Assert.Equal(0x00000014u, KmipOperation.Destroy);
    [Fact] public void Check()    => Assert.Equal(0x0000001Cu, KmipOperation.Check);

    [Fact]
    public void NoDuplicateValues()
    {
        var values = ConstantHelper.GetUIntConstants(typeof(KmipOperation));
        Assert.Equal(values.Count, new HashSet<uint>(values).Count);
    }
}

// ---------------------------------------------------------------------------
// ResultStatus
// ---------------------------------------------------------------------------

public class ResultStatusTests
{
    [Fact] public void Success()          => Assert.Equal(0x00000000u, KmipResultStatus.Success);
    [Fact] public void OperationFailed()  => Assert.Equal(0x00000001u, KmipResultStatus.OperationFailed);
    [Fact] public void OperationPending() => Assert.Equal(0x00000002u, KmipResultStatus.OperationPending);
    [Fact] public void OperationUndone()  => Assert.Equal(0x00000003u, KmipResultStatus.OperationUndone);

    [Fact]
    public void NoDuplicateValues()
    {
        var values = ConstantHelper.GetUIntConstants(typeof(KmipResultStatus));
        Assert.Equal(values.Count, new HashSet<uint>(values).Count);
    }
}

// ---------------------------------------------------------------------------
// Algorithm values -- KMIP 1.4 Section 9.1.3.2.13
// ---------------------------------------------------------------------------

public class AlgorithmTests
{
    [Fact] public void Des()        => Assert.Equal(0x00000001u, KmipAlgorithm.Des);
    [Fact] public void TripleDes()  => Assert.Equal(0x00000002u, KmipAlgorithm.TripleDes);
    [Fact] public void Aes()        => Assert.Equal(0x00000003u, KmipAlgorithm.Aes);
    [Fact] public void Rsa()        => Assert.Equal(0x00000004u, KmipAlgorithm.Rsa);
    [Fact] public void Dsa()        => Assert.Equal(0x00000005u, KmipAlgorithm.Dsa);
    [Fact] public void Ecdsa()      => Assert.Equal(0x00000006u, KmipAlgorithm.Ecdsa);
    [Fact] public void HmacSha1()   => Assert.Equal(0x00000007u, KmipAlgorithm.HmacSha1);
    [Fact] public void HmacSha256() => Assert.Equal(0x00000008u, KmipAlgorithm.HmacSha256);
    [Fact] public void HmacSha384() => Assert.Equal(0x00000009u, KmipAlgorithm.HmacSha384);
    [Fact] public void HmacSha512() => Assert.Equal(0x0000000Au, KmipAlgorithm.HmacSha512);

    [Fact]
    public void NoDuplicateValues()
    {
        var values = ConstantHelper.GetUIntConstants(typeof(KmipAlgorithm));
        Assert.Equal(values.Count, new HashSet<uint>(values).Count);
    }
}

// ---------------------------------------------------------------------------
// KeyFormatType values
// ---------------------------------------------------------------------------

public class KeyFormatTypeTests
{
    [Fact] public void Raw()                  => Assert.Equal(0x00000001u, KmipKeyFormatType.Raw);
    [Fact] public void Opaque()               => Assert.Equal(0x00000002u, KmipKeyFormatType.Opaque);
    [Fact] public void Pkcs1()                => Assert.Equal(0x00000003u, KmipKeyFormatType.Pkcs1);
    [Fact] public void Pkcs8()                => Assert.Equal(0x00000004u, KmipKeyFormatType.Pkcs8);
    [Fact] public void X509()                 => Assert.Equal(0x00000005u, KmipKeyFormatType.X509);
    [Fact] public void EcPrivateKey()         => Assert.Equal(0x00000006u, KmipKeyFormatType.EcPrivateKey);
    [Fact] public void TransparentSymmetric() => Assert.Equal(0x00000007u, KmipKeyFormatType.TransparentSymmetric);

    [Fact]
    public void NoDuplicateValues()
    {
        var values = ConstantHelper.GetUIntConstants(typeof(KmipKeyFormatType));
        Assert.Equal(values.Count, new HashSet<uint>(values).Count);
    }
}

// ---------------------------------------------------------------------------
// NameType values
// ---------------------------------------------------------------------------

public class NameTypeTests
{
    [Fact] public void UninterpretedTextString() => Assert.Equal(0x00000001u, KmipNameType.UninterpretedTextString);
    [Fact] public void Uri()                     => Assert.Equal(0x00000002u, KmipNameType.Uri);
}

// ---------------------------------------------------------------------------
// UsageMask -- bitmask values
// ---------------------------------------------------------------------------

public class UsageMaskTests
{
    [Fact] public void Sign()         => Assert.Equal(0x00000001u, KmipUsageMask.Sign);
    [Fact] public void Verify()       => Assert.Equal(0x00000002u, KmipUsageMask.Verify);
    [Fact] public void Encrypt()      => Assert.Equal(0x00000004u, KmipUsageMask.Encrypt);
    [Fact] public void Decrypt()      => Assert.Equal(0x00000008u, KmipUsageMask.Decrypt);
    [Fact] public void WrapKey()      => Assert.Equal(0x00000010u, KmipUsageMask.WrapKey);
    [Fact] public void UnwrapKey()    => Assert.Equal(0x00000020u, KmipUsageMask.UnwrapKey);
    [Fact] public void Export()       => Assert.Equal(0x00000040u, KmipUsageMask.Export);
    [Fact] public void DeriveKey()    => Assert.Equal(0x00000100u, KmipUsageMask.DeriveKey);
    [Fact] public void KeyAgreement() => Assert.Equal(0x00000800u, KmipUsageMask.KeyAgreement);

    [Fact]
    public void EncryptOrDecryptCombinesCorrectly()
    {
        Assert.Equal(0x0000000Cu, KmipUsageMask.Encrypt | KmipUsageMask.Decrypt);
    }

    [Fact]
    public void AllValuesAreDistinctBits()
    {
        var values = ConstantHelper.GetUIntConstants(typeof(KmipUsageMask));
        uint combined = 0;
        foreach (var v in values)
        {
            Assert.True((combined & v) == 0, $"value 0x{v:X8} overlaps with previous values");
            combined |= v;
        }
    }
}

// ---------------------------------------------------------------------------
// Tag values -- all should be in the 0x42XXXX range
// ---------------------------------------------------------------------------

public class TagRangeTests
{
    [Fact]
    public void AllTagValuesInKmipRange()
    {
        var fields = typeof(Tag).GetFields(BindingFlags.Public | BindingFlags.Static);
        foreach (var field in fields)
        {
            var value = (uint)field.GetValue(null)!;
            Assert.True(
                value >= 0x420000 && value <= 0x42FFFF,
                $"Tag.{field.Name} = 0x{value:X6} is outside 0x42XXXX range"
            );
        }
    }

    [Fact]
    public void NoDuplicateTagValues()
    {
        var values = ConstantHelper.GetUIntConstants(typeof(Tag));
        Assert.Equal(values.Count, new HashSet<uint>(values).Count);
    }
}

// ---------------------------------------------------------------------------
// ItemType constants
// ---------------------------------------------------------------------------

public class ItemTypeTests
{
    [Fact] public void Structure()   => Assert.Equal(0x01, ItemType.Structure);
    [Fact] public void Integer()     => Assert.Equal(0x02, ItemType.Integer);
    [Fact] public void LongInteger() => Assert.Equal(0x03, ItemType.LongInteger);
    [Fact] public void BigInteger()  => Assert.Equal(0x04, ItemType.BigInteger);
    [Fact] public void Enumeration() => Assert.Equal(0x05, ItemType.Enumeration);
    [Fact] public void Boolean()     => Assert.Equal(0x06, ItemType.Boolean);
    [Fact] public void TextString()  => Assert.Equal(0x07, ItemType.TextString);
    [Fact] public void ByteString()  => Assert.Equal(0x08, ItemType.ByteString);
    [Fact] public void DateTime()    => Assert.Equal(0x09, ItemType.DateTime);
    [Fact] public void Interval()    => Assert.Equal(0x0A, ItemType.Interval);
}
