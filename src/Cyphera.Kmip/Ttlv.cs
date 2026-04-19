// Copyright 2026 Horizon Digital Engineering LLC
// Licensed under the Apache License, Version 2.0

using System.Buffers.Binary;
using System.Text;

namespace Cyphera.Kmip;

/// <summary>
/// TTLV (Tag-Type-Length-Value) encoder/decoder for KMIP.
/// Implements the OASIS KMIP 1.4 binary encoding.
///
/// Each TTLV item:
///   Tag:    3 bytes (identifies the field)
///   Type:   1 byte  (data type)
///   Length: 4 bytes  (value length in bytes)
///   Value:  variable (padded to 8-byte alignment)
/// </summary>
public static class ItemType
{
    public const byte Structure   = 0x01;
    public const byte Integer     = 0x02;
    public const byte LongInteger = 0x03;
    public const byte BigInteger  = 0x04;
    public const byte Enumeration = 0x05;
    public const byte Boolean     = 0x06;
    public const byte TextString  = 0x07;
    public const byte ByteString  = 0x08;
    public const byte DateTime    = 0x09;
    public const byte Interval    = 0x0A;
}

/// <summary>A decoded TTLV item.</summary>
public sealed class TtlvItem
{
    public uint Tag { get; init; }
    public byte ItemType { get; init; }
    public int Length { get; init; }
    public int TotalLength { get; init; }

    // Value holders -- only one is populated based on ItemType
    public List<TtlvItem>? Children { get; init; }
    public int IntegerValue { get; init; }
    public long LongIntegerValue { get; init; }
    public uint EnumValue { get; init; }
    public bool BoolValue { get; init; }
    public string? TextValue { get; init; }
    public byte[]? BytesValue { get; init; }
    public long DateTimeValue { get; init; }
    public uint IntervalValue { get; init; }
}

/// <summary>TTLV encoder/decoder.</summary>
public static class Ttlv
{
    /// <summary>Pad a length to 8-byte alignment.</summary>
    private static int PadTo8(int len) => (len + 7) & ~7;

    /// <summary>Encode a single TTLV item.</summary>
    public static byte[] Encode(uint tag, byte type, ReadOnlySpan<byte> value)
    {
        int valueLen = value.Length;
        int padded = PadTo8(valueLen);
        var buf = new byte[8 + padded];

        // Tag: 3 bytes big-endian
        buf[0] = (byte)((tag >> 16) & 0xFF);
        buf[1] = (byte)((tag >> 8) & 0xFF);
        buf[2] = (byte)(tag & 0xFF);

        // Type: 1 byte
        buf[3] = type;

        // Length: 4 bytes big-endian
        BinaryPrimitives.WriteUInt32BigEndian(buf.AsSpan(4), (uint)valueLen);

        // Value + zero padding
        value.CopyTo(buf.AsSpan(8));

        return buf;
    }

    /// <summary>Encode a Structure containing child TTLV items.</summary>
    public static byte[] EncodeStructure(uint tag, params byte[][] children)
    {
        int totalLen = 0;
        foreach (var child in children)
            totalLen += child.Length;

        var inner = new byte[totalLen];
        int offset = 0;
        foreach (var child in children)
        {
            child.CopyTo(inner, offset);
            offset += child.Length;
        }

        return Encode(tag, Cyphera.Kmip.ItemType.Structure, inner);
    }

    /// <summary>Encode a 32-bit integer.</summary>
    public static byte[] EncodeInteger(uint tag, int value)
    {
        var buf = new byte[4];
        BinaryPrimitives.WriteInt32BigEndian(buf, value);
        return Encode(tag, Cyphera.Kmip.ItemType.Integer, buf);
    }

    /// <summary>Encode a 64-bit long integer.</summary>
    public static byte[] EncodeLongInteger(uint tag, long value)
    {
        var buf = new byte[8];
        BinaryPrimitives.WriteInt64BigEndian(buf, value);
        return Encode(tag, Cyphera.Kmip.ItemType.LongInteger, buf);
    }

    /// <summary>Encode an enumeration (32-bit unsigned).</summary>
    public static byte[] EncodeEnum(uint tag, uint value)
    {
        var buf = new byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(buf, value);
        return Encode(tag, Cyphera.Kmip.ItemType.Enumeration, buf);
    }

    /// <summary>Encode a boolean.</summary>
    public static byte[] EncodeBoolean(uint tag, bool value)
    {
        var buf = new byte[8];
        BinaryPrimitives.WriteInt64BigEndian(buf, value ? 1L : 0L);
        return Encode(tag, Cyphera.Kmip.ItemType.Boolean, buf);
    }

    /// <summary>Encode a text string (UTF-8).</summary>
    public static byte[] EncodeTextString(uint tag, string value)
    {
        return Encode(tag, Cyphera.Kmip.ItemType.TextString, Encoding.UTF8.GetBytes(value));
    }

    /// <summary>Encode a byte string (raw bytes).</summary>
    public static byte[] EncodeByteString(uint tag, byte[] value)
    {
        return Encode(tag, Cyphera.Kmip.ItemType.ByteString, value);
    }

    /// <summary>Encode a DateTime (64-bit POSIX timestamp).</summary>
    public static byte[] EncodeDateTime(uint tag, DateTimeOffset date)
    {
        var buf = new byte[8];
        BinaryPrimitives.WriteInt64BigEndian(buf, date.ToUnixTimeSeconds());
        return Encode(tag, Cyphera.Kmip.ItemType.DateTime, buf);
    }

    /// <summary>Maximum nesting depth for TTLV structures.</summary>
    private const int MaxDecodeDepth = 32;

    /// <summary>Decode a TTLV buffer into a parsed item.</summary>
    public static TtlvItem Decode(ReadOnlySpan<byte> buf, int offset = 0)
    {
        return DecodeDepth(buf, offset, 0);
    }

    private static TtlvItem DecodeDepth(ReadOnlySpan<byte> buf, int offset, int depth)
    {
        if (depth > MaxDecodeDepth)
            throw new InvalidOperationException("TTLV: maximum nesting depth exceeded");

        if (buf.Length - offset < 8)
            throw new InvalidOperationException("TTLV buffer too short for header");

        uint tag = ((uint)buf[offset] << 16) | ((uint)buf[offset + 1] << 8) | buf[offset + 2];
        byte type = buf[offset + 3];
        int length = (int)BinaryPrimitives.ReadUInt32BigEndian(buf.Slice(offset + 4));
        int padded = PadTo8(length);
        int totalLength = 8 + padded;
        int valueStart = offset + 8;

        // Bounds check: ensure declared length fits within buffer.
        if (valueStart + padded > buf.Length)
            throw new InvalidOperationException(
                $"TTLV: declared length {length} exceeds buffer (have {buf.Length - valueStart} bytes)");

        switch (type)
        {
            case Cyphera.Kmip.ItemType.Structure:
            {
                var children = new List<TtlvItem>();
                int pos = valueStart;
                int end = valueStart + length;
                while (pos < end)
                {
                    var child = DecodeDepth(buf, pos, depth + 1);
                    children.Add(child);
                    pos += child.TotalLength;
                }
                return new TtlvItem
                {
                    Tag = tag, ItemType = type, Length = length,
                    TotalLength = totalLength, Children = children,
                };
            }
            case Cyphera.Kmip.ItemType.Integer:
                return new TtlvItem
                {
                    Tag = tag, ItemType = type, Length = length,
                    TotalLength = totalLength,
                    IntegerValue = BinaryPrimitives.ReadInt32BigEndian(buf.Slice(valueStart)),
                };
            case Cyphera.Kmip.ItemType.LongInteger:
                return new TtlvItem
                {
                    Tag = tag, ItemType = type, Length = length,
                    TotalLength = totalLength,
                    LongIntegerValue = BinaryPrimitives.ReadInt64BigEndian(buf.Slice(valueStart)),
                };
            case Cyphera.Kmip.ItemType.Enumeration:
                return new TtlvItem
                {
                    Tag = tag, ItemType = type, Length = length,
                    TotalLength = totalLength,
                    EnumValue = BinaryPrimitives.ReadUInt32BigEndian(buf.Slice(valueStart)),
                };
            case Cyphera.Kmip.ItemType.Boolean:
                return new TtlvItem
                {
                    Tag = tag, ItemType = type, Length = length,
                    TotalLength = totalLength,
                    BoolValue = BinaryPrimitives.ReadInt64BigEndian(buf.Slice(valueStart)) != 0,
                };
            case Cyphera.Kmip.ItemType.TextString:
                return new TtlvItem
                {
                    Tag = tag, ItemType = type, Length = length,
                    TotalLength = totalLength,
                    TextValue = Encoding.UTF8.GetString(buf.Slice(valueStart, length)),
                };
            case Cyphera.Kmip.ItemType.ByteString:
                return new TtlvItem
                {
                    Tag = tag, ItemType = type, Length = length,
                    TotalLength = totalLength,
                    BytesValue = buf.Slice(valueStart, length).ToArray(),
                };
            case Cyphera.Kmip.ItemType.DateTime:
                return new TtlvItem
                {
                    Tag = tag, ItemType = type, Length = length,
                    TotalLength = totalLength,
                    DateTimeValue = BinaryPrimitives.ReadInt64BigEndian(buf.Slice(valueStart)),
                };
            case Cyphera.Kmip.ItemType.BigInteger:
                return new TtlvItem
                {
                    Tag = tag, ItemType = type, Length = length,
                    TotalLength = totalLength,
                    BytesValue = buf.Slice(valueStart, length).ToArray(),
                };
            case Cyphera.Kmip.ItemType.Interval:
                return new TtlvItem
                {
                    Tag = tag, ItemType = type, Length = length,
                    TotalLength = totalLength,
                    IntervalValue = BinaryPrimitives.ReadUInt32BigEndian(buf.Slice(valueStart)),
                };
            default:
                return new TtlvItem
                {
                    Tag = tag, ItemType = type, Length = length,
                    TotalLength = totalLength,
                    BytesValue = buf.Slice(valueStart, length).ToArray(),
                };
        }
    }

    /// <summary>Find the first child with a given tag within a decoded structure.</summary>
    public static TtlvItem? FindChild(TtlvItem item, uint tag)
    {
        if (item.Children == null) return null;
        return item.Children.Find(c => c.Tag == tag);
    }

    /// <summary>Find all children with a given tag within a decoded structure.</summary>
    public static List<TtlvItem> FindChildren(TtlvItem item, uint tag)
    {
        if (item.Children == null) return new List<TtlvItem>();
        return item.Children.FindAll(c => c.Tag == tag);
    }
}
