// Copyright 2026 Horizon Digital Engineering LLC
// Licensed under the Apache License, Version 2.0

using Cyphera.Kmip;
using Xunit;

namespace Cyphera.Kmip.Tests;

public class TtlvTests
{
    [Fact]
    public void EncodeDecodeInteger()
    {
        var encoded = Ttlv.EncodeInteger(0x42006A, 1);
        var decoded = Ttlv.Decode(encoded);
        Assert.Equal(0x42006Au, decoded.Tag);
        Assert.Equal(ItemType.Integer, decoded.ItemType);
        Assert.Equal(1, decoded.IntegerValue);
    }

    [Fact]
    public void EncodeDecodeEnumeration()
    {
        var encoded = Ttlv.EncodeEnum(0x42005C, 0x0000000A);
        var decoded = Ttlv.Decode(encoded);
        Assert.Equal(0x42005Cu, decoded.Tag);
        Assert.Equal(ItemType.Enumeration, decoded.ItemType);
        Assert.Equal(0x0000000Au, decoded.EnumValue);
    }

    [Fact]
    public void EncodeDecodeTextString()
    {
        var encoded = Ttlv.EncodeTextString(0x420055, "my-key");
        var decoded = Ttlv.Decode(encoded);
        Assert.Equal(0x420055u, decoded.Tag);
        Assert.Equal(ItemType.TextString, decoded.ItemType);
        Assert.Equal("my-key", decoded.TextValue);
    }

    [Fact]
    public void EncodeDecodeByteString()
    {
        var key = new byte[] { 0xaa, 0xbb, 0xcc, 0xdd };
        var encoded = Ttlv.EncodeByteString(0x420043, key);
        var decoded = Ttlv.Decode(encoded);
        Assert.Equal(0x420043u, decoded.Tag);
        Assert.Equal(ItemType.ByteString, decoded.ItemType);
        Assert.Equal(key, decoded.BytesValue);
    }

    [Fact]
    public void EncodeDecodeBoolean()
    {
        var encoded = Ttlv.EncodeBoolean(0x420008, true);
        var decoded = Ttlv.Decode(encoded);
        Assert.Equal(ItemType.Boolean, decoded.ItemType);
        Assert.True(decoded.BoolValue);
    }

    [Fact]
    public void EncodeDecodeStructureWithChildren()
    {
        var encoded = Ttlv.EncodeStructure(0x420069,
            Ttlv.EncodeInteger(0x42006A, 1),
            Ttlv.EncodeInteger(0x42006B, 4)
        );
        var decoded = Ttlv.Decode(encoded);
        Assert.Equal(0x420069u, decoded.Tag);
        Assert.Equal(ItemType.Structure, decoded.ItemType);
        Assert.NotNull(decoded.Children);
        Assert.Equal(2, decoded.Children!.Count);
        Assert.Equal(1, decoded.Children[0].IntegerValue);
        Assert.Equal(4, decoded.Children[1].IntegerValue);
    }

    [Fact]
    public void FindChildLocatesByTag()
    {
        var encoded = Ttlv.EncodeStructure(0x420069,
            Ttlv.EncodeInteger(0x42006A, 1),
            Ttlv.EncodeInteger(0x42006B, 4)
        );
        var decoded = Ttlv.Decode(encoded);
        var child = Ttlv.FindChild(decoded, 0x42006B);
        Assert.NotNull(child);
        Assert.Equal(4, child!.IntegerValue);
    }

    [Fact]
    public void TextStringPaddedTo8ByteAlignment()
    {
        // "hello" = 5 bytes -> padded to 8 bytes -> total TTLV = 16 bytes
        var encoded = Ttlv.EncodeTextString(0x420055, "hello");
        Assert.Equal(16, encoded.Length); // 8 header + 8 padded value
    }

    [Fact]
    public void EmptyTextString()
    {
        var encoded = Ttlv.EncodeTextString(0x420055, "");
        var decoded = Ttlv.Decode(encoded);
        Assert.Equal("", decoded.TextValue);
    }

    [Fact]
    public void RoundTripNestedStructures()
    {
        var encoded = Ttlv.EncodeStructure(0x420078,
            Ttlv.EncodeStructure(0x420077,
                Ttlv.EncodeStructure(0x420069,
                    Ttlv.EncodeInteger(0x42006A, 1),
                    Ttlv.EncodeInteger(0x42006B, 4)
                ),
                Ttlv.EncodeInteger(0x42000D, 1)
            )
        );
        var decoded = Ttlv.Decode(encoded);
        Assert.Equal(0x420078u, decoded.Tag);
        var header = Ttlv.FindChild(decoded, 0x420077);
        Assert.NotNull(header);
        var version = Ttlv.FindChild(header!, 0x420069);
        Assert.NotNull(version);
        var major = Ttlv.FindChild(version!, 0x42006A);
        Assert.NotNull(major);
        Assert.Equal(1, major!.IntegerValue);
    }
}
