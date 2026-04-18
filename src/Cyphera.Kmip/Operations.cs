// Copyright 2026 Horizon Digital Engineering LLC
// Licensed under the Apache License, Version 2.0

namespace Cyphera.Kmip;

/// <summary>
/// KMIP request/response builders for Locate, Get, Create operations.
/// Builds KMIP 1.4 request messages and parses response messages.
/// </summary>
public static class Operations
{
    /// <summary>Protocol version: KMIP 1.4</summary>
    public const int ProtocolMajor = 1;
    public const int ProtocolMinor = 4;

    /// <summary>Build the request header (included in every request).</summary>
    private static byte[] BuildRequestHeader(int batchCount = 1)
    {
        return Ttlv.EncodeStructure(Tag.RequestHeader,
            Ttlv.EncodeStructure(Tag.ProtocolVersion,
                Ttlv.EncodeInteger(Tag.ProtocolVersionMajor, ProtocolMajor),
                Ttlv.EncodeInteger(Tag.ProtocolVersionMinor, ProtocolMinor)
            ),
            Ttlv.EncodeInteger(Tag.BatchCount, batchCount)
        );
    }

    /// <summary>Build a Locate request -- find keys by name.</summary>
    public static byte[] BuildLocateRequest(string name)
    {
        var payload = Ttlv.EncodeStructure(Tag.RequestPayload,
            Ttlv.EncodeStructure(Tag.Attribute,
                Ttlv.EncodeTextString(Tag.AttributeName, "Name"),
                Ttlv.EncodeStructure(Tag.AttributeValue,
                    Ttlv.EncodeTextString(Tag.NameValue, name),
                    Ttlv.EncodeEnum(Tag.NameType, KmipNameType.UninterpretedTextString)
                )
            )
        );

        var batchItem = Ttlv.EncodeStructure(Tag.BatchItem,
            Ttlv.EncodeEnum(Tag.Operation, KmipOperation.Locate),
            payload
        );

        return Ttlv.EncodeStructure(Tag.RequestMessage,
            BuildRequestHeader(),
            batchItem
        );
    }

    /// <summary>Build a Get request -- fetch key material by unique ID.</summary>
    public static byte[] BuildGetRequest(string uniqueId)
    {
        var payload = Ttlv.EncodeStructure(Tag.RequestPayload,
            Ttlv.EncodeTextString(Tag.UniqueIdentifier, uniqueId)
        );

        var batchItem = Ttlv.EncodeStructure(Tag.BatchItem,
            Ttlv.EncodeEnum(Tag.Operation, KmipOperation.Get),
            payload
        );

        return Ttlv.EncodeStructure(Tag.RequestMessage,
            BuildRequestHeader(),
            batchItem
        );
    }

    /// <summary>Build a Create request -- create a new symmetric key.</summary>
    public static byte[] BuildCreateRequest(string name, uint algorithm = KmipAlgorithm.Aes, int length = 256)
    {
        var payload = Ttlv.EncodeStructure(Tag.RequestPayload,
            Ttlv.EncodeEnum(Tag.ObjectType, KmipObjectType.SymmetricKey),
            Ttlv.EncodeStructure(Tag.TemplateAttribute,
                Ttlv.EncodeStructure(Tag.Attribute,
                    Ttlv.EncodeTextString(Tag.AttributeName, "Cryptographic Algorithm"),
                    Ttlv.EncodeEnum(Tag.AttributeValue, algorithm)
                ),
                Ttlv.EncodeStructure(Tag.Attribute,
                    Ttlv.EncodeTextString(Tag.AttributeName, "Cryptographic Length"),
                    Ttlv.EncodeInteger(Tag.AttributeValue, length)
                ),
                Ttlv.EncodeStructure(Tag.Attribute,
                    Ttlv.EncodeTextString(Tag.AttributeName, "Cryptographic Usage Mask"),
                    Ttlv.EncodeInteger(Tag.AttributeValue, (int)(KmipUsageMask.Encrypt | KmipUsageMask.Decrypt))
                ),
                Ttlv.EncodeStructure(Tag.Attribute,
                    Ttlv.EncodeTextString(Tag.AttributeName, "Name"),
                    Ttlv.EncodeStructure(Tag.AttributeValue,
                        Ttlv.EncodeTextString(Tag.NameValue, name),
                        Ttlv.EncodeEnum(Tag.NameType, KmipNameType.UninterpretedTextString)
                    )
                )
            )
        );

        var batchItem = Ttlv.EncodeStructure(Tag.BatchItem,
            Ttlv.EncodeEnum(Tag.Operation, KmipOperation.Create),
            payload
        );

        return Ttlv.EncodeStructure(Tag.RequestMessage,
            BuildRequestHeader(),
            batchItem
        );
    }

    /// <summary>Parse a KMIP response message.</summary>
    public static KmipResponse ParseResponse(byte[] data)
    {
        var msg = Ttlv.Decode(data);
        if (msg.Tag != Tag.ResponseMessage)
            throw new KmipException($"Expected ResponseMessage (0x42007B), got 0x{msg.Tag:X6}");

        var batchItem = Ttlv.FindChild(msg, Tag.BatchItem)
            ?? throw new KmipException("No BatchItem in response");

        var operationItem = Ttlv.FindChild(batchItem, Tag.Operation);
        var statusItem = Ttlv.FindChild(batchItem, Tag.ResultStatus);
        var reasonItem = Ttlv.FindChild(batchItem, Tag.ResultReason);
        var messageItem = Ttlv.FindChild(batchItem, Tag.ResultMessage);
        var payloadItem = Ttlv.FindChild(batchItem, Tag.ResponsePayload);

        var result = new KmipResponse
        {
            Operation = operationItem?.EnumValue,
            ResultStatus = statusItem?.EnumValue,
            ResultReason = reasonItem?.EnumValue,
            ResultMessage = messageItem?.TextValue,
            Payload = payloadItem,
        };

        if (result.ResultStatus != KmipResultStatus.Success)
        {
            var errMsg = result.ResultMessage
                ?? $"KMIP operation failed (status={result.ResultStatus})";
            throw new KmipException(errMsg)
            {
                ResultStatus = result.ResultStatus,
                ResultReason = result.ResultReason,
            };
        }

        return result;
    }

    /// <summary>Parse a Locate response payload.</summary>
    public static LocateResult ParseLocatePayload(TtlvItem payload)
    {
        var ids = Ttlv.FindChildren(payload, Tag.UniqueIdentifier);
        return new LocateResult
        {
            UniqueIdentifiers = ids
                .Where(i => i.TextValue != null)
                .Select(i => i.TextValue!)
                .ToList(),
        };
    }

    /// <summary>Parse a Get response payload.</summary>
    public static GetResult ParseGetPayload(TtlvItem payload)
    {
        var uid = Ttlv.FindChild(payload, Tag.UniqueIdentifier);
        var objType = Ttlv.FindChild(payload, Tag.ObjectType);

        // Navigate: SymmetricKey -> KeyBlock -> KeyValue -> KeyMaterial
        byte[]? keyMaterial = null;
        var symKey = Ttlv.FindChild(payload, Tag.SymmetricKey);
        if (symKey != null)
        {
            var keyBlock = Ttlv.FindChild(symKey, Tag.KeyBlock);
            if (keyBlock != null)
            {
                var keyValue = Ttlv.FindChild(keyBlock, Tag.KeyValue);
                if (keyValue != null)
                {
                    var material = Ttlv.FindChild(keyValue, Tag.KeyMaterial);
                    if (material != null)
                        keyMaterial = material.BytesValue;
                }
            }
        }

        return new GetResult
        {
            ObjectType = objType?.EnumValue,
            UniqueIdentifier = uid?.TextValue,
            KeyMaterial = keyMaterial,
        };
    }

    /// <summary>Parse a Create response payload.</summary>
    public static CreateResult ParseCreatePayload(TtlvItem payload)
    {
        var uid = Ttlv.FindChild(payload, Tag.UniqueIdentifier);
        var objType = Ttlv.FindChild(payload, Tag.ObjectType);

        return new CreateResult
        {
            ObjectType = objType?.EnumValue,
            UniqueIdentifier = uid?.TextValue,
        };
    }
}

/// <summary>Parsed KMIP response.</summary>
public sealed class KmipResponse
{
    public uint? Operation { get; init; }
    public uint? ResultStatus { get; init; }
    public uint? ResultReason { get; init; }
    public string? ResultMessage { get; init; }
    public TtlvItem? Payload { get; init; }
}

/// <summary>Parsed Locate response.</summary>
public sealed class LocateResult
{
    public List<string> UniqueIdentifiers { get; init; } = new();
}

/// <summary>Parsed Get response.</summary>
public sealed class GetResult
{
    public uint? ObjectType { get; init; }
    public string? UniqueIdentifier { get; init; }
    public byte[]? KeyMaterial { get; init; }
}

/// <summary>Parsed Create response.</summary>
public sealed class CreateResult
{
    public uint? ObjectType { get; init; }
    public string? UniqueIdentifier { get; init; }
}

/// <summary>KMIP operation exception.</summary>
public sealed class KmipException : Exception
{
    public uint? ResultStatus { get; init; }
    public uint? ResultReason { get; init; }

    public KmipException(string message) : base(message) { }
    public KmipException(string message, Exception inner) : base(message, inner) { }
}
