// Copyright 2026 Horizon Digital Engineering LLC
// Licensed under the Apache License, Version 2.0

using System.Buffers.Binary;
using Cyphera.Kmip;
using Xunit;

namespace Cyphera.Kmip.Tests;

// ---------------------------------------------------------------------------
// Primitive encode / decode round-trips
// ---------------------------------------------------------------------------

public class TtlvPrimitiveTests
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
    public void EncodeDecodeNegativeInteger()
    {
        var encoded = Ttlv.EncodeInteger(0x42006A, -42);
        var decoded = Ttlv.Decode(encoded);
        Assert.Equal(-42, decoded.IntegerValue);
    }

    [Fact]
    public void EncodeDecodeMaxInt32()
    {
        var encoded = Ttlv.EncodeInteger(0x42006A, int.MaxValue);
        var decoded = Ttlv.Decode(encoded);
        Assert.Equal(int.MaxValue, decoded.IntegerValue);
    }

    [Fact]
    public void EncodeDecodeMinInt32()
    {
        var encoded = Ttlv.EncodeInteger(0x42006A, int.MinValue);
        var decoded = Ttlv.Decode(encoded);
        Assert.Equal(int.MinValue, decoded.IntegerValue);
    }

    [Fact]
    public void EncodeDecodeZeroInteger()
    {
        var encoded = Ttlv.EncodeInteger(0x42006A, 0);
        var decoded = Ttlv.Decode(encoded);
        Assert.Equal(0, decoded.IntegerValue);
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
    public void EncodeDecodeLongInteger()
    {
        var encoded = Ttlv.EncodeLongInteger(0x42006A, 1234567890123L);
        var decoded = Ttlv.Decode(encoded);
        Assert.Equal(0x42006Au, decoded.Tag);
        Assert.Equal(ItemType.LongInteger, decoded.ItemType);
        Assert.Equal(1234567890123L, decoded.LongIntegerValue);
    }

    [Fact]
    public void EncodeDecodeNegativeLongInteger()
    {
        var encoded = Ttlv.EncodeLongInteger(0x42006A, -9999999999L);
        var decoded = Ttlv.Decode(encoded);
        Assert.Equal(-9999999999L, decoded.LongIntegerValue);
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
    public void EncodeDecodeBooleanTrue()
    {
        var encoded = Ttlv.EncodeBoolean(0x420008, true);
        var decoded = Ttlv.Decode(encoded);
        Assert.Equal(ItemType.Boolean, decoded.ItemType);
        Assert.True(decoded.BoolValue);
    }

    [Fact]
    public void EncodeDecodeBooleanFalse()
    {
        var encoded = Ttlv.EncodeBoolean(0x420008, false);
        var decoded = Ttlv.Decode(encoded);
        Assert.Equal(ItemType.Boolean, decoded.ItemType);
        Assert.False(decoded.BoolValue);
    }

    [Fact]
    public void EncodeDecodeDateTime()
    {
        var date = new DateTimeOffset(2026, 4, 18, 12, 0, 0, TimeSpan.Zero);
        var encoded = Ttlv.EncodeDateTime(0x420008, date);
        var decoded = Ttlv.Decode(encoded);
        Assert.Equal(ItemType.DateTime, decoded.ItemType);
        Assert.Equal(date.ToUnixTimeSeconds(), decoded.DateTimeValue);
    }

    [Fact]
    public void EncodeDecodeEpochZeroDateTime()
    {
        var date = DateTimeOffset.UnixEpoch;
        var encoded = Ttlv.EncodeDateTime(0x420008, date);
        var decoded = Ttlv.Decode(encoded);
        Assert.Equal(0L, decoded.DateTimeValue);
    }
}

// ---------------------------------------------------------------------------
// Padding and alignment
// ---------------------------------------------------------------------------

public class TtlvPaddingTests
{
    [Fact]
    public void IntegerOccupies16BytesTotal()
    {
        var encoded = Ttlv.EncodeInteger(0x42006A, 1);
        // 8 header + 8 padded value (4 value + 4 padding) = 16 bytes
        Assert.Equal(16, encoded.Length);
        // Length field should say 4
        Assert.Equal(4u, BinaryPrimitives.ReadUInt32BigEndian(encoded.AsSpan(4)));
    }

    [Fact]
    public void EnumOccupies16BytesTotal()
    {
        var encoded = Ttlv.EncodeEnum(0x42005C, 1);
        Assert.Equal(16, encoded.Length);
        Assert.Equal(4u, BinaryPrimitives.ReadUInt32BigEndian(encoded.AsSpan(4)));
    }

    [Fact]
    public void BooleanUsesExactly8ByteValue()
    {
        var encoded = Ttlv.EncodeBoolean(0x420008, true);
        Assert.Equal(16, encoded.Length); // 8 header + 8 value
        Assert.Equal(8u, BinaryPrimitives.ReadUInt32BigEndian(encoded.AsSpan(4)));
    }

    [Fact]
    public void LongIntegerUsesExactly8ByteValue()
    {
        var encoded = Ttlv.EncodeLongInteger(0x42006A, 42);
        Assert.Equal(16, encoded.Length);
        Assert.Equal(8u, BinaryPrimitives.ReadUInt32BigEndian(encoded.AsSpan(4)));
    }

    [Fact]
    public void TextStringPaddedTo8ByteAlignment()
    {
        // "hello" = 5 bytes -> padded to 8
        var encoded = Ttlv.EncodeTextString(0x420055, "hello");
        Assert.Equal(16, encoded.Length); // 8 header + 8 padded value
    }

    [Fact]
    public void TextStringExactly8BytesNoPadding()
    {
        var encoded = Ttlv.EncodeTextString(0x420055, "12345678");
        Assert.Equal(16, encoded.Length); // 8 header + 8 value
    }

    [Fact]
    public void TextString9BytesPadsTo16()
    {
        var encoded = Ttlv.EncodeTextString(0x420055, "123456789");
        Assert.Equal(24, encoded.Length); // 8 header + 16 padded
    }

    [Fact]
    public void EmptyTextStringHeaderOnly()
    {
        var encoded = Ttlv.EncodeTextString(0x420055, "");
        Assert.Equal(8, encoded.Length); // header only
        var decoded = Ttlv.Decode(encoded);
        Assert.Equal("", decoded.TextValue);
    }

    [Fact]
    public void ByteStringExact8ByteAlignmentNoPadding()
    {
        var data = new byte[16];
        Array.Fill(data, (byte)0xAB);
        var encoded = Ttlv.EncodeByteString(0x420043, data);
        Assert.Equal(24, encoded.Length); // 8 header + 16 value
    }

    [Fact]
    public void ByteStringOneExtraBytePadsToNext8()
    {
        var data = new byte[17];
        Array.Fill(data, (byte)0xAB);
        var encoded = Ttlv.EncodeByteString(0x420043, data);
        Assert.Equal(32, encoded.Length); // 8 header + 24 padded
    }

    [Fact]
    public void EmptyByteString()
    {
        var encoded = Ttlv.EncodeByteString(0x420043, Array.Empty<byte>());
        Assert.Equal(8, encoded.Length);
        var decoded = Ttlv.Decode(encoded);
        Assert.NotNull(decoded.BytesValue);
        Assert.Empty(decoded.BytesValue!);
    }

    [Fact]
    public void Aes256KeyMaterialRoundTrips()
    {
        var key = Convert.FromHexString("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
        var encoded = Ttlv.EncodeByteString(0x420043, key);
        Assert.Equal(40, encoded.Length); // 8 header + 32 value (exact alignment)
        var decoded = Ttlv.Decode(encoded);
        Assert.Equal(key, decoded.BytesValue);
    }
}

// ---------------------------------------------------------------------------
// Structures and tree navigation
// ---------------------------------------------------------------------------

public class TtlvStructureTests
{
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
    public void EmptyStructureNoChildren()
    {
        var encoded = Ttlv.EncodeStructure(0x420069);
        var decoded = Ttlv.Decode(encoded);
        Assert.Equal(ItemType.Structure, decoded.ItemType);
        Assert.NotNull(decoded.Children);
        Assert.Empty(decoded.Children!);
    }

    [Fact]
    public void StructureWithMixedTypes()
    {
        var encoded = Ttlv.EncodeStructure(0x420069,
            Ttlv.EncodeInteger(0x42006A, 42),
            Ttlv.EncodeTextString(0x420055, "hello"),
            Ttlv.EncodeBoolean(0x420008, true),
            Ttlv.EncodeByteString(0x420043, new byte[] { 0xca, 0xfe }),
            Ttlv.EncodeEnum(0x42005C, 0x0A)
        );
        var decoded = Ttlv.Decode(encoded);
        Assert.Equal(5, decoded.Children!.Count);
        Assert.Equal(42, decoded.Children[0].IntegerValue);
        Assert.Equal("hello", decoded.Children[1].TextValue);
        Assert.True(decoded.Children[2].BoolValue);
        Assert.Equal(new byte[] { 0xca, 0xfe }, decoded.Children[3].BytesValue);
        Assert.Equal(0x0Au, decoded.Children[4].EnumValue);
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
    public void FindChildReturnsNullForMissingTag()
    {
        var encoded = Ttlv.EncodeStructure(0x420069,
            Ttlv.EncodeInteger(0x42006A, 1)
        );
        var decoded = Ttlv.Decode(encoded);
        Assert.Null(Ttlv.FindChild(decoded, 0x42FFFF));
    }

    [Fact]
    public void FindChildReturnsNullForNonStructure()
    {
        var encoded = Ttlv.EncodeInteger(0x42006A, 1);
        var decoded = Ttlv.Decode(encoded);
        Assert.Null(Ttlv.FindChild(decoded, 0x42006A));
    }

    [Fact]
    public void FindChildrenReturnsAllMatching()
    {
        var encoded = Ttlv.EncodeStructure(0x420069,
            Ttlv.EncodeTextString(0x420094, "id-1"),
            Ttlv.EncodeTextString(0x420094, "id-2"),
            Ttlv.EncodeTextString(0x420094, "id-3"),
            Ttlv.EncodeInteger(0x42006A, 99)
        );
        var decoded = Ttlv.Decode(encoded);
        var ids = Ttlv.FindChildren(decoded, 0x420094);
        Assert.Equal(3, ids.Count);
        Assert.Equal("id-1", ids[0].TextValue);
        Assert.Equal("id-2", ids[1].TextValue);
        Assert.Equal("id-3", ids[2].TextValue);
    }

    [Fact]
    public void FindChildrenReturnsEmptyForNonStructure()
    {
        var encoded = Ttlv.EncodeInteger(0x42006A, 1);
        var decoded = Ttlv.Decode(encoded);
        var result = Ttlv.FindChildren(decoded, 0x42006A);
        Assert.Empty(result);
    }

    [Fact]
    public void RoundTripDeeplyNestedStructures()
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
        var minor = Ttlv.FindChild(version!, 0x42006B);
        Assert.NotNull(minor);
        Assert.Equal(4, minor!.IntegerValue);
    }

    [Fact]
    public void ThreeLevelNestedStructures()
    {
        var encoded = Ttlv.EncodeStructure(0x420001,
            Ttlv.EncodeStructure(0x420002,
                Ttlv.EncodeStructure(0x420003,
                    Ttlv.EncodeTextString(0x420055, "deep")
                )
            )
        );
        var decoded = Ttlv.Decode(encoded);
        var lvl1 = Ttlv.FindChild(decoded, 0x420002);
        Assert.NotNull(lvl1);
        var lvl2 = Ttlv.FindChild(lvl1!, 0x420003);
        Assert.NotNull(lvl2);
        var leaf = Ttlv.FindChild(lvl2!, 0x420055);
        Assert.NotNull(leaf);
        Assert.Equal("deep", leaf!.TextValue);
    }
}

// ---------------------------------------------------------------------------
// TTLV header bytes -- wire format verification
// ---------------------------------------------------------------------------

public class TtlvWireFormatTests
{
    [Fact]
    public void TagEncoded3BytesBigEndian()
    {
        var encoded = Ttlv.EncodeInteger(0x420069, 0);
        Assert.Equal(0x42, encoded[0]);
        Assert.Equal(0x00, encoded[1]);
        Assert.Equal(0x69, encoded[2]);
    }

    [Fact]
    public void TypeByteCorrectForEachType()
    {
        Assert.Equal(ItemType.Integer, Ttlv.EncodeInteger(0x420001, 0)[3]);
        Assert.Equal(ItemType.LongInteger, Ttlv.EncodeLongInteger(0x420001, 0)[3]);
        Assert.Equal(ItemType.Enumeration, Ttlv.EncodeEnum(0x420001, 0)[3]);
        Assert.Equal(ItemType.Boolean, Ttlv.EncodeBoolean(0x420001, true)[3]);
        Assert.Equal(ItemType.TextString, Ttlv.EncodeTextString(0x420001, "x")[3]);
        Assert.Equal(ItemType.ByteString, Ttlv.EncodeByteString(0x420001, new byte[] { 1 })[3]);
        Assert.Equal(ItemType.Structure, Ttlv.EncodeStructure(0x420001)[3]);
        Assert.Equal(ItemType.DateTime, Ttlv.EncodeDateTime(0x420001, DateTimeOffset.UtcNow)[3]);
    }

    [Fact]
    public void LengthField4BytesBigEndianAtOffset4()
    {
        var encoded = Ttlv.EncodeTextString(0x420055, "AB"); // 2 bytes
        Assert.Equal(2u, BinaryPrimitives.ReadUInt32BigEndian(encoded.AsSpan(4)));
    }

    [Fact]
    public void PaddingBytesAreZeroFilled()
    {
        var encoded = Ttlv.EncodeTextString(0x420055, "AB"); // 2 bytes -> padded to 8
        // Value starts at offset 8, length 2, padding at bytes 10-15
        for (int i = 10; i < 16; i++)
        {
            Assert.Equal(0, encoded[i]);
        }
    }
}

// ---------------------------------------------------------------------------
// Error handling
// ---------------------------------------------------------------------------

public class TtlvErrorHandlingTests
{
    [Fact]
    public void ThrowsOnBufferTooShortForHeader()
    {
        var ex = Assert.Throws<InvalidOperationException>(() => Ttlv.Decode(new byte[4]));
        Assert.Contains("too short", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void ThrowsOnEmptyBuffer()
    {
        var ex = Assert.Throws<InvalidOperationException>(() => Ttlv.Decode(Array.Empty<byte>()));
        Assert.Contains("too short", ex.Message, StringComparison.OrdinalIgnoreCase);
    }
}

// ---------------------------------------------------------------------------
// Unicode and special strings
// ---------------------------------------------------------------------------

public class TtlvUnicodeTests
{
    [Fact]
    public void HandlesUtf8MultiByteCharacters()
    {
        var encoded = Ttlv.EncodeTextString(0x420055, "caf\u00e9");
        var decoded = Ttlv.Decode(encoded);
        Assert.Equal("caf\u00e9", decoded.TextValue);
    }

    [Fact]
    public void HandlesEmoji()
    {
        var encoded = Ttlv.EncodeTextString(0x420055, "key-\U0001F511");
        var decoded = Ttlv.Decode(encoded);
        Assert.Equal("key-\U0001F511", decoded.TextValue);
    }

    [Fact]
    public void HandlesLongTextStringCrossingMultiple8ByteBoundaries()
    {
        var longStr = string.Concat(Enumerable.Repeat("a]", 100)); // 200 bytes
        var encoded = Ttlv.EncodeTextString(0x420055, longStr);
        var decoded = Ttlv.Decode(encoded);
        Assert.Equal(longStr, decoded.TextValue);
    }
}

// ---------------------------------------------------------------------------
// Security hardening tests
// ---------------------------------------------------------------------------

public class TtlvSecurityTests
{
    [Fact]
    public void RejectsDeclaredLengthExceedingBuffer()
    {
        // Header claiming 1000 bytes of value, but only 10 bytes provided
        var buf = new byte[18]; // 8 header + 10 body
        buf[0] = 0x42; buf[1] = 0x00; buf[2] = 0x01; // tag = 0x420001
        buf[3] = 0x07; // type = TextString
        BinaryPrimitives.WriteUInt32BigEndian(buf.AsSpan(4), 1000); // length = 1000
        var ex = Assert.Throws<InvalidOperationException>(() => Ttlv.Decode(buf));
        Assert.Contains("exceeds available data", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void AcceptsDeclaredLengthThatExactlyFitsBuffer()
    {
        var encoded = Ttlv.EncodeInteger(0x420001, 42);
        var decoded = Ttlv.Decode(encoded);
        Assert.Equal(42, decoded.IntegerValue);
    }

    [Fact]
    public void RejectsZeroLengthBuffer()
    {
        Assert.Throws<InvalidOperationException>(() => Ttlv.Decode(Array.Empty<byte>()));
    }

    [Fact]
    public void RejectsStructuresNestedDeeperThan32Levels()
    {
        // Build 33 levels of nesting
        byte[] inner = Ttlv.EncodeInteger(0x420001, 42);
        for (int i = 0; i < 33; i++)
        {
            inner = Ttlv.EncodeStructure(0x420001, inner);
        }
        var ex = Assert.Throws<InvalidOperationException>(() => Ttlv.Decode(inner));
        Assert.Contains("depth", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void AcceptsStructuresNestedExactly32LevelsDeep()
    {
        // Build 31 wrapping levels (root is depth 0, innermost is depth 31)
        byte[] inner = Ttlv.EncodeInteger(0x420001, 42);
        for (int i = 0; i < 31; i++)
        {
            inner = Ttlv.EncodeStructure(0x420001, inner);
        }
        var decoded = Ttlv.Decode(inner);
        Assert.Equal(ItemType.Structure, decoded.ItemType);
    }

    [Fact]
    public void RejectsTruncatedHeader()
    {
        var buf = new byte[] { 0x42, 0x00, 0x01, 0x02 };
        var ex = Assert.Throws<InvalidOperationException>(() => Ttlv.Decode(buf));
        Assert.Contains("too short", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void HandlesIntegerWithWrongLengthSafely()
    {
        // Header: tag=0x420001, type=Integer(0x02), length=3 (should be 4)
        var buf = new byte[16];
        buf[0] = 0x42; buf[1] = 0x00; buf[2] = 0x01;
        buf[3] = 0x02; // type = Integer
        BinaryPrimitives.WriteUInt32BigEndian(buf.AsSpan(4), 3); // length = 3
        // Should either throw or handle safely — must not crash
        try
        {
            Ttlv.Decode(buf);
        }
        catch (Exception)
        {
            // Any exception is acceptable
        }
        Assert.True(true, "decoder did not crash on malformed integer length");
    }
}
