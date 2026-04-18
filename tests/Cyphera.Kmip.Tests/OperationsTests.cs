// Copyright 2026 Horizon Digital Engineering LLC
// Licensed under the Apache License, Version 2.0

using Cyphera.Kmip;
using Xunit;

namespace Cyphera.Kmip.Tests;

// ---------------------------------------------------------------------------
// Request building
// ---------------------------------------------------------------------------

public class OperationsRequestTests
{
    [Fact]
    public void BuildLocateRequestProducesValidTtlvStructure()
    {
        var request = Operations.BuildLocateRequest("test-key");
        var decoded = Ttlv.Decode(request);
        Assert.Equal(Tag.RequestMessage, decoded.Tag);
        Assert.Equal(ItemType.Structure, decoded.ItemType);
    }

    [Fact]
    public void BuildLocateRequestContainsProtocolVersion14()
    {
        var decoded = Ttlv.Decode(Operations.BuildLocateRequest("k"));
        var header = Ttlv.FindChild(decoded, Tag.RequestHeader);
        Assert.NotNull(header);
        var version = Ttlv.FindChild(header!, Tag.ProtocolVersion);
        Assert.NotNull(version);
        var major = Ttlv.FindChild(version!, Tag.ProtocolVersionMajor);
        var minor = Ttlv.FindChild(version!, Tag.ProtocolVersionMinor);
        Assert.Equal(Operations.ProtocolMajor, major!.IntegerValue);
        Assert.Equal(Operations.ProtocolMinor, minor!.IntegerValue);
    }

    [Fact]
    public void BuildLocateRequestHasBatchCount1()
    {
        var decoded = Ttlv.Decode(Operations.BuildLocateRequest("k"));
        var header = Ttlv.FindChild(decoded, Tag.RequestHeader);
        var count = Ttlv.FindChild(header!, Tag.BatchCount);
        Assert.Equal(1, count!.IntegerValue);
    }

    [Fact]
    public void BuildLocateRequestHasLocateOperation()
    {
        var decoded = Ttlv.Decode(Operations.BuildLocateRequest("k"));
        var batch = Ttlv.FindChild(decoded, Tag.BatchItem);
        var op = Ttlv.FindChild(batch!, Tag.Operation);
        Assert.Equal(KmipOperation.Locate, op!.EnumValue);
    }

    [Fact]
    public void BuildLocateRequestContainsNameAttribute()
    {
        var decoded = Ttlv.Decode(Operations.BuildLocateRequest("my-key"));
        var batch = Ttlv.FindChild(decoded, Tag.BatchItem);
        var payload = Ttlv.FindChild(batch!, Tag.RequestPayload);
        var attr = Ttlv.FindChild(payload!, Tag.Attribute);
        var attrName = Ttlv.FindChild(attr!, Tag.AttributeName);
        Assert.Equal("Name", attrName!.TextValue);
        var attrValue = Ttlv.FindChild(attr!, Tag.AttributeValue);
        var nameValue = Ttlv.FindChild(attrValue!, Tag.NameValue);
        Assert.Equal("my-key", nameValue!.TextValue);
    }

    [Fact]
    public void BuildGetRequestProducesValidTtlvStructure()
    {
        var request = Operations.BuildGetRequest("unique-id-123");
        var decoded = Ttlv.Decode(request);
        Assert.Equal(Tag.RequestMessage, decoded.Tag);
    }

    [Fact]
    public void BuildGetRequestHasGetOperation()
    {
        var decoded = Ttlv.Decode(Operations.BuildGetRequest("uid"));
        var batch = Ttlv.FindChild(decoded, Tag.BatchItem);
        var op = Ttlv.FindChild(batch!, Tag.Operation);
        Assert.Equal(KmipOperation.Get, op!.EnumValue);
    }

    [Fact]
    public void BuildGetRequestContainsUniqueIdentifier()
    {
        var decoded = Ttlv.Decode(Operations.BuildGetRequest("uid-456"));
        var batch = Ttlv.FindChild(decoded, Tag.BatchItem);
        var payload = Ttlv.FindChild(batch!, Tag.RequestPayload);
        var uid = Ttlv.FindChild(payload!, Tag.UniqueIdentifier);
        Assert.Equal("uid-456", uid!.TextValue);
    }

    [Fact]
    public void BuildCreateRequestProducesValidTtlvStructure()
    {
        var request = Operations.BuildCreateRequest("new-key");
        var decoded = Ttlv.Decode(request);
        Assert.Equal(Tag.RequestMessage, decoded.Tag);
    }

    [Fact]
    public void BuildCreateRequestHasCreateOperation()
    {
        var decoded = Ttlv.Decode(Operations.BuildCreateRequest("k"));
        var batch = Ttlv.FindChild(decoded, Tag.BatchItem);
        var op = Ttlv.FindChild(batch!, Tag.Operation);
        Assert.Equal(KmipOperation.Create, op!.EnumValue);
    }

    [Fact]
    public void BuildCreateRequestUsesSymmetricKeyObjectType()
    {
        var decoded = Ttlv.Decode(Operations.BuildCreateRequest("k"));
        var batch = Ttlv.FindChild(decoded, Tag.BatchItem);
        var payload = Ttlv.FindChild(batch!, Tag.RequestPayload);
        var objType = Ttlv.FindChild(payload!, Tag.ObjectType);
        Assert.Equal(KmipObjectType.SymmetricKey, objType!.EnumValue);
    }

    [Fact]
    public void BuildCreateRequestDefaultsToAesAlgorithm()
    {
        var decoded = Ttlv.Decode(Operations.BuildCreateRequest("k"));
        var batch = Ttlv.FindChild(decoded, Tag.BatchItem);
        var payload = Ttlv.FindChild(batch!, Tag.RequestPayload);
        var tmpl = Ttlv.FindChild(payload!, Tag.TemplateAttribute);
        var attrs = Ttlv.FindChildren(tmpl!, Tag.Attribute);
        var algoAttr = attrs.Find(a =>
            Ttlv.FindChild(a, Tag.AttributeName)?.TextValue == "Cryptographic Algorithm");
        Assert.NotNull(algoAttr);
        var algoValue = Ttlv.FindChild(algoAttr!, Tag.AttributeValue);
        Assert.Equal(KmipAlgorithm.Aes, algoValue!.EnumValue);
    }

    [Fact]
    public void BuildCreateRequestDefaultsTo256BitLength()
    {
        var decoded = Ttlv.Decode(Operations.BuildCreateRequest("k"));
        var batch = Ttlv.FindChild(decoded, Tag.BatchItem);
        var payload = Ttlv.FindChild(batch!, Tag.RequestPayload);
        var tmpl = Ttlv.FindChild(payload!, Tag.TemplateAttribute);
        var attrs = Ttlv.FindChildren(tmpl!, Tag.Attribute);
        var lenAttr = attrs.Find(a =>
            Ttlv.FindChild(a, Tag.AttributeName)?.TextValue == "Cryptographic Length");
        Assert.NotNull(lenAttr);
        var lenValue = Ttlv.FindChild(lenAttr!, Tag.AttributeValue);
        Assert.Equal(256, lenValue!.IntegerValue);
    }

    [Fact]
    public void BuildCreateRequestIncludesEncryptDecryptUsageMask()
    {
        var decoded = Ttlv.Decode(Operations.BuildCreateRequest("k"));
        var batch = Ttlv.FindChild(decoded, Tag.BatchItem);
        var payload = Ttlv.FindChild(batch!, Tag.RequestPayload);
        var tmpl = Ttlv.FindChild(payload!, Tag.TemplateAttribute);
        var attrs = Ttlv.FindChildren(tmpl!, Tag.Attribute);
        var usageAttr = attrs.Find(a =>
            Ttlv.FindChild(a, Tag.AttributeName)?.TextValue == "Cryptographic Usage Mask");
        Assert.NotNull(usageAttr);
        var usageValue = Ttlv.FindChild(usageAttr!, Tag.AttributeValue);
        Assert.Equal((int)(KmipUsageMask.Encrypt | KmipUsageMask.Decrypt), usageValue!.IntegerValue);
    }

    [Fact]
    public void BuildCreateRequestIncludesKeyNameInTemplate()
    {
        var decoded = Ttlv.Decode(Operations.BuildCreateRequest("prod-key"));
        var batch = Ttlv.FindChild(decoded, Tag.BatchItem);
        var payload = Ttlv.FindChild(batch!, Tag.RequestPayload);
        var tmpl = Ttlv.FindChild(payload!, Tag.TemplateAttribute);
        var attrs = Ttlv.FindChildren(tmpl!, Tag.Attribute);
        var nameAttr = attrs.Find(a =>
            Ttlv.FindChild(a, Tag.AttributeName)?.TextValue == "Name");
        Assert.NotNull(nameAttr);
        var nameStruct = Ttlv.FindChild(nameAttr!, Tag.AttributeValue);
        var nameValue = Ttlv.FindChild(nameStruct!, Tag.NameValue);
        Assert.Equal("prod-key", nameValue!.TextValue);
    }

    [Fact]
    public void BuildCreateRequestAcceptsCustomAlgorithmAndLength()
    {
        var decoded = Ttlv.Decode(Operations.BuildCreateRequest("k", KmipAlgorithm.TripleDes, 192));
        var batch = Ttlv.FindChild(decoded, Tag.BatchItem);
        var payload = Ttlv.FindChild(batch!, Tag.RequestPayload);
        var tmpl = Ttlv.FindChild(payload!, Tag.TemplateAttribute);
        var attrs = Ttlv.FindChildren(tmpl!, Tag.Attribute);

        var algoAttr = attrs.Find(a =>
            Ttlv.FindChild(a, Tag.AttributeName)?.TextValue == "Cryptographic Algorithm");
        var algoValue = Ttlv.FindChild(algoAttr!, Tag.AttributeValue);
        Assert.Equal(KmipAlgorithm.TripleDes, algoValue!.EnumValue);

        var lenAttr = attrs.Find(a =>
            Ttlv.FindChild(a, Tag.AttributeName)?.TextValue == "Cryptographic Length");
        var lenValue = Ttlv.FindChild(lenAttr!, Tag.AttributeValue);
        Assert.Equal(192, lenValue!.IntegerValue);
    }
}

// ---------------------------------------------------------------------------
// Response parsing
// ---------------------------------------------------------------------------

public class OperationsResponseTests
{
    /// <summary>Build a mock KMIP response message for testing.</summary>
    private static byte[] BuildMockResponse(uint operation, uint status, params byte[][] payloadChildren)
    {
        var batchParts = new List<byte[]>
        {
            Ttlv.EncodeEnum(Tag.Operation, operation),
            Ttlv.EncodeEnum(Tag.ResultStatus, status),
        };
        if (payloadChildren.Length > 0)
        {
            batchParts.Add(Ttlv.EncodeStructure(Tag.ResponsePayload, payloadChildren));
        }

        return Ttlv.EncodeStructure(Tag.ResponseMessage,
            Ttlv.EncodeStructure(Tag.ResponseHeader,
                Ttlv.EncodeStructure(Tag.ProtocolVersion,
                    Ttlv.EncodeInteger(Tag.ProtocolVersionMajor, 1),
                    Ttlv.EncodeInteger(Tag.ProtocolVersionMinor, 4)
                ),
                Ttlv.EncodeInteger(Tag.BatchCount, 1)
            ),
            Ttlv.EncodeStructure(Tag.BatchItem, batchParts.ToArray())
        );
    }

    [Fact]
    public void ParseResponseExtractsOperationAndStatusOnSuccess()
    {
        var response = BuildMockResponse(KmipOperation.Locate, KmipResultStatus.Success,
            Ttlv.EncodeTextString(Tag.UniqueIdentifier, "id-1"));
        var result = Operations.ParseResponse(response);
        Assert.Equal(KmipOperation.Locate, result.Operation);
        Assert.Equal(KmipResultStatus.Success, result.ResultStatus);
    }

    [Fact]
    public void ParseResponseThrowsOnOperationFailure()
    {
        var batchParts = new[]
        {
            Ttlv.EncodeEnum(Tag.Operation, KmipOperation.Get),
            Ttlv.EncodeEnum(Tag.ResultStatus, KmipResultStatus.OperationFailed),
            Ttlv.EncodeTextString(Tag.ResultMessage, "Item Not Found"),
        };
        var response = Ttlv.EncodeStructure(Tag.ResponseMessage,
            Ttlv.EncodeStructure(Tag.ResponseHeader,
                Ttlv.EncodeStructure(Tag.ProtocolVersion,
                    Ttlv.EncodeInteger(Tag.ProtocolVersionMajor, 1),
                    Ttlv.EncodeInteger(Tag.ProtocolVersionMinor, 4)
                ),
                Ttlv.EncodeInteger(Tag.BatchCount, 1)
            ),
            Ttlv.EncodeStructure(Tag.BatchItem, batchParts)
        );

        var ex = Assert.Throws<KmipException>(() => Operations.ParseResponse(response));
        Assert.Contains("Item Not Found", ex.Message);
    }

    [Fact]
    public void ParseResponseThrowsOnNonResponseMessageTag()
    {
        var badMsg = Ttlv.EncodeStructure(Tag.RequestMessage);
        var ex = Assert.Throws<KmipException>(() => Operations.ParseResponse(badMsg));
        Assert.Contains("ResponseMessage", ex.Message);
    }

    [Fact]
    public void ParseLocatePayloadExtractsUniqueIdentifiers()
    {
        var payload = Ttlv.Decode(Ttlv.EncodeStructure(Tag.ResponsePayload,
            Ttlv.EncodeTextString(Tag.UniqueIdentifier, "uid-1"),
            Ttlv.EncodeTextString(Tag.UniqueIdentifier, "uid-2"),
            Ttlv.EncodeTextString(Tag.UniqueIdentifier, "uid-3")
        ));
        var result = Operations.ParseLocatePayload(payload);
        Assert.Equal(new[] { "uid-1", "uid-2", "uid-3" }, result.UniqueIdentifiers);
    }

    [Fact]
    public void ParseLocatePayloadHandlesEmptyResult()
    {
        var payload = Ttlv.Decode(Ttlv.EncodeStructure(Tag.ResponsePayload));
        var result = Operations.ParseLocatePayload(payload);
        Assert.Empty(result.UniqueIdentifiers);
    }

    [Fact]
    public void ParseLocatePayloadHandlesSingleResult()
    {
        var payload = Ttlv.Decode(Ttlv.EncodeStructure(Tag.ResponsePayload,
            Ttlv.EncodeTextString(Tag.UniqueIdentifier, "only-one")
        ));
        var result = Operations.ParseLocatePayload(payload);
        Assert.Equal(new[] { "only-one" }, result.UniqueIdentifiers);
    }

    [Fact]
    public void ParseGetPayloadExtractsKeyMaterial()
    {
        var keyBytes = Convert.FromHexString("0123456789abcdef0123456789abcdef");
        var payload = Ttlv.Decode(Ttlv.EncodeStructure(Tag.ResponsePayload,
            Ttlv.EncodeTextString(Tag.UniqueIdentifier, "uid-99"),
            Ttlv.EncodeEnum(Tag.ObjectType, KmipObjectType.SymmetricKey),
            Ttlv.EncodeStructure(Tag.SymmetricKey,
                Ttlv.EncodeStructure(Tag.KeyBlock,
                    Ttlv.EncodeEnum(Tag.KeyFormatType, KmipKeyFormatType.Raw),
                    Ttlv.EncodeStructure(Tag.KeyValue,
                        Ttlv.EncodeByteString(Tag.KeyMaterial, keyBytes)
                    )
                )
            )
        ));
        var result = Operations.ParseGetPayload(payload);
        Assert.Equal("uid-99", result.UniqueIdentifier);
        Assert.Equal(KmipObjectType.SymmetricKey, result.ObjectType);
        Assert.Equal(keyBytes, result.KeyMaterial);
    }

    [Fact]
    public void ParseGetPayloadReturnsNullKeyMaterialWhenNoSymmetricKey()
    {
        var payload = Ttlv.Decode(Ttlv.EncodeStructure(Tag.ResponsePayload,
            Ttlv.EncodeTextString(Tag.UniqueIdentifier, "uid-50"),
            Ttlv.EncodeEnum(Tag.ObjectType, KmipObjectType.Certificate)
        ));
        var result = Operations.ParseGetPayload(payload);
        Assert.Equal("uid-50", result.UniqueIdentifier);
        Assert.Null(result.KeyMaterial);
    }

    [Fact]
    public void ParseCreatePayloadExtractsObjectTypeAndUniqueId()
    {
        var payload = Ttlv.Decode(Ttlv.EncodeStructure(Tag.ResponsePayload,
            Ttlv.EncodeEnum(Tag.ObjectType, KmipObjectType.SymmetricKey),
            Ttlv.EncodeTextString(Tag.UniqueIdentifier, "new-uid-7")
        ));
        var result = Operations.ParseCreatePayload(payload);
        Assert.Equal(KmipObjectType.SymmetricKey, result.ObjectType);
        Assert.Equal("new-uid-7", result.UniqueIdentifier);
    }
}

// ---------------------------------------------------------------------------
// Round-trip: build -> encode -> decode -> verify
// ---------------------------------------------------------------------------

public class OperationsRoundTripTests
{
    [Fact]
    public void LocateRequestRoundTrips()
    {
        var request = Operations.BuildLocateRequest("round-trip-key");
        var reEncoded = Operations.BuildLocateRequest("round-trip-key");
        Assert.Equal(request, reEncoded);
    }

    [Fact]
    public void GetRequestRoundTrips()
    {
        var request = Operations.BuildGetRequest("uid-abc");
        var decoded = Ttlv.Decode(request);
        Assert.Equal(Tag.RequestMessage, decoded.Tag);
        var batch = Ttlv.FindChild(decoded, Tag.BatchItem);
        var payload = Ttlv.FindChild(batch!, Tag.RequestPayload);
        var uid = Ttlv.FindChild(payload!, Tag.UniqueIdentifier);
        Assert.Equal("uid-abc", uid!.TextValue);
    }

    [Fact]
    public void CreateRequestRoundTrips()
    {
        var request = Operations.BuildCreateRequest("rt-key", KmipAlgorithm.Aes, 128);
        var decoded = Ttlv.Decode(request);
        Assert.Equal(Tag.RequestMessage, decoded.Tag);
        var batch = Ttlv.FindChild(decoded, Tag.BatchItem);
        var op = Ttlv.FindChild(batch!, Tag.Operation);
        Assert.Equal(KmipOperation.Create, op!.EnumValue);
    }
}
