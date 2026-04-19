// Copyright 2026 Horizon Digital Engineering LLC
// Licensed under the Apache License, Version 2.0

using Cyphera.Kmip;
using Xunit;

namespace Cyphera.Kmip.Tests;

// ---------------------------------------------------------------------------
// Request building -- all 27 operations
// ---------------------------------------------------------------------------

public class OperationsRequestTests
{
    // -----------------------------------------------------------------------
    // Helper: verify a request has valid structure, correct operation, and UID
    // -----------------------------------------------------------------------

    private static TtlvItem DecodeAndVerifyRequest(byte[] request, uint expectedOp)
    {
        var decoded = Ttlv.Decode(request);
        Assert.Equal(Tag.RequestMessage, decoded.Tag);
        Assert.Equal(ItemType.Structure, decoded.ItemType);
        var batch = Ttlv.FindChild(decoded, Tag.BatchItem)!;
        var op = Ttlv.FindChild(batch, Tag.Operation)!;
        Assert.Equal(expectedOp, op.EnumValue);
        return decoded;
    }

    private static TtlvItem GetPayload(TtlvItem decoded)
    {
        var batch = Ttlv.FindChild(decoded, Tag.BatchItem)!;
        return Ttlv.FindChild(batch, Tag.RequestPayload)!;
    }

    // -----------------------------------------------------------------------
    // 1. Create
    // -----------------------------------------------------------------------

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

    // -----------------------------------------------------------------------
    // 2. CreateKeyPair
    // -----------------------------------------------------------------------

    [Fact]
    public void BuildCreateKeyPairRequestHasCorrectOperation()
    {
        DecodeAndVerifyRequest(
            Operations.BuildCreateKeyPairRequest("kp", KmipAlgorithm.Rsa, 2048),
            KmipOperation.CreateKeyPair);
    }

    [Fact]
    public void BuildCreateKeyPairRequestIncludesSignVerifyUsageMask()
    {
        var decoded = DecodeAndVerifyRequest(
            Operations.BuildCreateKeyPairRequest("kp", KmipAlgorithm.Rsa, 2048),
            KmipOperation.CreateKeyPair);
        var payload = GetPayload(decoded);
        var tmpl = Ttlv.FindChild(payload, Tag.TemplateAttribute)!;
        var attrs = Ttlv.FindChildren(tmpl, Tag.Attribute);
        var usageAttr = attrs.Find(a =>
            Ttlv.FindChild(a, Tag.AttributeName)?.TextValue == "Cryptographic Usage Mask");
        Assert.NotNull(usageAttr);
        var usageValue = Ttlv.FindChild(usageAttr!, Tag.AttributeValue);
        Assert.Equal((int)(KmipUsageMask.Sign | KmipUsageMask.Verify), usageValue!.IntegerValue);
    }

    // -----------------------------------------------------------------------
    // 3. Register
    // -----------------------------------------------------------------------

    [Fact]
    public void BuildRegisterRequestHasCorrectOperation()
    {
        var material = new byte[] { 0x01, 0x02, 0x03 };
        DecodeAndVerifyRequest(
            Operations.BuildRegisterRequest(KmipObjectType.SymmetricKey, material, "reg-key", KmipAlgorithm.Aes, 256),
            KmipOperation.Register);
    }

    [Fact]
    public void BuildRegisterRequestContainsKeyMaterial()
    {
        var material = new byte[] { 0xAA, 0xBB, 0xCC };
        var decoded = DecodeAndVerifyRequest(
            Operations.BuildRegisterRequest(KmipObjectType.SymmetricKey, material, "reg-key", KmipAlgorithm.Aes, 256),
            KmipOperation.Register);
        var payload = GetPayload(decoded);
        var symKey = Ttlv.FindChild(payload, Tag.SymmetricKey)!;
        var keyBlock = Ttlv.FindChild(symKey, Tag.KeyBlock)!;
        var keyValue = Ttlv.FindChild(keyBlock, Tag.KeyValue)!;
        var keyMat = Ttlv.FindChild(keyValue, Tag.KeyMaterial)!;
        Assert.Equal(material, keyMat.BytesValue);
    }

    [Fact]
    public void BuildRegisterRequestOmitsTemplateAttributeWhenNameEmpty()
    {
        var material = new byte[] { 0x01 };
        var decoded = DecodeAndVerifyRequest(
            Operations.BuildRegisterRequest(KmipObjectType.SymmetricKey, material, "", KmipAlgorithm.Aes, 128),
            KmipOperation.Register);
        var payload = GetPayload(decoded);
        Assert.Null(Ttlv.FindChild(payload, Tag.TemplateAttribute));
    }

    // -----------------------------------------------------------------------
    // 4. ReKey
    // -----------------------------------------------------------------------

    [Fact]
    public void BuildReKeyRequestHasCorrectOperation()
    {
        var decoded = DecodeAndVerifyRequest(
            Operations.BuildReKeyRequest("uid-rk"),
            KmipOperation.ReKey);
        var payload = GetPayload(decoded);
        var uid = Ttlv.FindChild(payload, Tag.UniqueIdentifier)!;
        Assert.Equal("uid-rk", uid.TextValue);
    }

    // -----------------------------------------------------------------------
    // 5. DeriveKey
    // -----------------------------------------------------------------------

    [Fact]
    public void BuildDeriveKeyRequestHasCorrectOperation()
    {
        var derivData = new byte[] { 0x01, 0x02 };
        DecodeAndVerifyRequest(
            Operations.BuildDeriveKeyRequest("uid-dk", derivData, "derived", 128),
            KmipOperation.DeriveKey);
    }

    [Fact]
    public void BuildDeriveKeyRequestContainsDerivationParameters()
    {
        var derivData = new byte[] { 0xDE, 0xAD };
        var decoded = DecodeAndVerifyRequest(
            Operations.BuildDeriveKeyRequest("uid-dk", derivData, "derived", 128),
            KmipOperation.DeriveKey);
        var payload = GetPayload(decoded);
        var derivParams = Ttlv.FindChild(payload, Tag.DerivationParameters)!;
        var derivDataItem = Ttlv.FindChild(derivParams, Tag.DerivationData)!;
        Assert.Equal(derivData, derivDataItem.BytesValue);
    }

    // -----------------------------------------------------------------------
    // 6. Locate (covered above)
    // -----------------------------------------------------------------------

    // -----------------------------------------------------------------------
    // 7. Check
    // -----------------------------------------------------------------------

    [Fact]
    public void BuildCheckRequestHasCorrectOperation()
    {
        var decoded = DecodeAndVerifyRequest(
            Operations.BuildCheckRequest("uid-chk"),
            KmipOperation.Check);
        var payload = GetPayload(decoded);
        var uid = Ttlv.FindChild(payload, Tag.UniqueIdentifier)!;
        Assert.Equal("uid-chk", uid.TextValue);
    }

    // -----------------------------------------------------------------------
    // 8. Get (covered above)
    // -----------------------------------------------------------------------

    // -----------------------------------------------------------------------
    // 9. GetAttributes
    // -----------------------------------------------------------------------

    [Fact]
    public void BuildGetAttributesRequestHasCorrectOperation()
    {
        DecodeAndVerifyRequest(
            Operations.BuildGetAttributesRequest("uid-ga"),
            KmipOperation.GetAttributes);
    }

    // -----------------------------------------------------------------------
    // 10. GetAttributeList
    // -----------------------------------------------------------------------

    [Fact]
    public void BuildGetAttributeListRequestHasCorrectOperation()
    {
        DecodeAndVerifyRequest(
            Operations.BuildGetAttributeListRequest("uid-gal"),
            KmipOperation.GetAttributeList);
    }

    // -----------------------------------------------------------------------
    // 11. AddAttribute
    // -----------------------------------------------------------------------

    [Fact]
    public void BuildAddAttributeRequestHasCorrectOperation()
    {
        DecodeAndVerifyRequest(
            Operations.BuildAddAttributeRequest("uid-aa", "x-custom", "val"),
            KmipOperation.AddAttribute);
    }

    [Fact]
    public void BuildAddAttributeRequestContainsAttribute()
    {
        var decoded = DecodeAndVerifyRequest(
            Operations.BuildAddAttributeRequest("uid-aa", "x-custom", "val"),
            KmipOperation.AddAttribute);
        var payload = GetPayload(decoded);
        var attr = Ttlv.FindChild(payload, Tag.Attribute)!;
        var attrName = Ttlv.FindChild(attr, Tag.AttributeName)!;
        Assert.Equal("x-custom", attrName.TextValue);
        var attrValue = Ttlv.FindChild(attr, Tag.AttributeValue)!;
        Assert.Equal("val", attrValue.TextValue);
    }

    // -----------------------------------------------------------------------
    // 12. ModifyAttribute
    // -----------------------------------------------------------------------

    [Fact]
    public void BuildModifyAttributeRequestHasCorrectOperation()
    {
        DecodeAndVerifyRequest(
            Operations.BuildModifyAttributeRequest("uid-ma", "x-custom", "newval"),
            KmipOperation.ModifyAttribute);
    }

    // -----------------------------------------------------------------------
    // 13. DeleteAttribute
    // -----------------------------------------------------------------------

    [Fact]
    public void BuildDeleteAttributeRequestHasCorrectOperation()
    {
        DecodeAndVerifyRequest(
            Operations.BuildDeleteAttributeRequest("uid-da", "x-custom"),
            KmipOperation.DeleteAttribute);
    }

    [Fact]
    public void BuildDeleteAttributeRequestContainsAttributeNameOnly()
    {
        var decoded = DecodeAndVerifyRequest(
            Operations.BuildDeleteAttributeRequest("uid-da", "x-custom"),
            KmipOperation.DeleteAttribute);
        var payload = GetPayload(decoded);
        var attr = Ttlv.FindChild(payload, Tag.Attribute)!;
        var attrName = Ttlv.FindChild(attr, Tag.AttributeName)!;
        Assert.Equal("x-custom", attrName.TextValue);
        // No attribute value in delete
        Assert.Null(Ttlv.FindChild(attr, Tag.AttributeValue));
    }

    // -----------------------------------------------------------------------
    // 14. ObtainLease
    // -----------------------------------------------------------------------

    [Fact]
    public void BuildObtainLeaseRequestHasCorrectOperation()
    {
        DecodeAndVerifyRequest(
            Operations.BuildObtainLeaseRequest("uid-ol"),
            KmipOperation.ObtainLease);
    }

    // -----------------------------------------------------------------------
    // 15. Activate
    // -----------------------------------------------------------------------

    [Fact]
    public void BuildActivateRequestHasCorrectOperation()
    {
        DecodeAndVerifyRequest(
            Operations.BuildActivateRequest("uid-act"),
            KmipOperation.Activate);
    }

    // -----------------------------------------------------------------------
    // 16. Revoke
    // -----------------------------------------------------------------------

    [Fact]
    public void BuildRevokeRequestHasCorrectOperation()
    {
        DecodeAndVerifyRequest(
            Operations.BuildRevokeRequest("uid-rev", 1),
            KmipOperation.Revoke);
    }

    [Fact]
    public void BuildRevokeRequestContainsRevocationReason()
    {
        var decoded = DecodeAndVerifyRequest(
            Operations.BuildRevokeRequest("uid-rev", 0x00000002),
            KmipOperation.Revoke);
        var payload = GetPayload(decoded);
        var rr = Ttlv.FindChild(payload, Tag.RevocationReason)!;
        var rrc = Ttlv.FindChild(rr, Tag.RevocationReasonCode)!;
        Assert.Equal(0x00000002u, rrc.EnumValue);
    }

    // -----------------------------------------------------------------------
    // 17. Destroy
    // -----------------------------------------------------------------------

    [Fact]
    public void BuildDestroyRequestHasCorrectOperation()
    {
        DecodeAndVerifyRequest(
            Operations.BuildDestroyRequest("uid-del"),
            KmipOperation.Destroy);
    }

    // -----------------------------------------------------------------------
    // 18. Archive
    // -----------------------------------------------------------------------

    [Fact]
    public void BuildArchiveRequestHasCorrectOperation()
    {
        DecodeAndVerifyRequest(
            Operations.BuildArchiveRequest("uid-arc"),
            KmipOperation.Archive);
    }

    // -----------------------------------------------------------------------
    // 19. Recover
    // -----------------------------------------------------------------------

    [Fact]
    public void BuildRecoverRequestHasCorrectOperation()
    {
        DecodeAndVerifyRequest(
            Operations.BuildRecoverRequest("uid-rec"),
            KmipOperation.Recover);
    }

    // -----------------------------------------------------------------------
    // 20. Query
    // -----------------------------------------------------------------------

    [Fact]
    public void BuildQueryRequestHasCorrectOperation()
    {
        DecodeAndVerifyRequest(
            Operations.BuildQueryRequest(),
            KmipOperation.Query);
    }

    [Fact]
    public void BuildQueryRequestHasEmptyPayload()
    {
        var decoded = DecodeAndVerifyRequest(
            Operations.BuildQueryRequest(),
            KmipOperation.Query);
        var payload = GetPayload(decoded);
        Assert.NotNull(payload.Children);
        Assert.Empty(payload.Children!);
    }

    // -----------------------------------------------------------------------
    // 21. Poll
    // -----------------------------------------------------------------------

    [Fact]
    public void BuildPollRequestHasCorrectOperation()
    {
        DecodeAndVerifyRequest(
            Operations.BuildPollRequest(),
            KmipOperation.Poll);
    }

    // -----------------------------------------------------------------------
    // 22. DiscoverVersions
    // -----------------------------------------------------------------------

    [Fact]
    public void BuildDiscoverVersionsRequestHasCorrectOperation()
    {
        DecodeAndVerifyRequest(
            Operations.BuildDiscoverVersionsRequest(),
            KmipOperation.DiscoverVersions);
    }

    // -----------------------------------------------------------------------
    // 23. Encrypt
    // -----------------------------------------------------------------------

    [Fact]
    public void BuildEncryptRequestHasCorrectOperation()
    {
        DecodeAndVerifyRequest(
            Operations.BuildEncryptRequest("uid-enc", new byte[] { 0x01 }),
            KmipOperation.Encrypt);
    }

    [Fact]
    public void BuildEncryptRequestContainsData()
    {
        var plaintext = new byte[] { 0xCA, 0xFE, 0xBA, 0xBE };
        var decoded = DecodeAndVerifyRequest(
            Operations.BuildEncryptRequest("uid-enc", plaintext),
            KmipOperation.Encrypt);
        var payload = GetPayload(decoded);
        var data = Ttlv.FindChild(payload, Tag.Data)!;
        Assert.Equal(plaintext, data.BytesValue);
    }

    // -----------------------------------------------------------------------
    // 24. Decrypt
    // -----------------------------------------------------------------------

    [Fact]
    public void BuildDecryptRequestHasCorrectOperation()
    {
        DecodeAndVerifyRequest(
            Operations.BuildDecryptRequest("uid-dec", new byte[] { 0x01 }),
            KmipOperation.Decrypt);
    }

    [Fact]
    public void BuildDecryptRequestIncludesNonceWhenProvided()
    {
        var nonce = new byte[] { 0x11, 0x22, 0x33 };
        var decoded = DecodeAndVerifyRequest(
            Operations.BuildDecryptRequest("uid-dec", new byte[] { 0x01 }, nonce),
            KmipOperation.Decrypt);
        var payload = GetPayload(decoded);
        var nonceItem = Ttlv.FindChild(payload, Tag.IVCounterNonce)!;
        Assert.Equal(nonce, nonceItem.BytesValue);
    }

    [Fact]
    public void BuildDecryptRequestOmitsNonceWhenNull()
    {
        var decoded = DecodeAndVerifyRequest(
            Operations.BuildDecryptRequest("uid-dec", new byte[] { 0x01 }),
            KmipOperation.Decrypt);
        var payload = GetPayload(decoded);
        Assert.Null(Ttlv.FindChild(payload, Tag.IVCounterNonce));
    }

    // -----------------------------------------------------------------------
    // 25. Sign
    // -----------------------------------------------------------------------

    [Fact]
    public void BuildSignRequestHasCorrectOperation()
    {
        DecodeAndVerifyRequest(
            Operations.BuildSignRequest("uid-sign", new byte[] { 0x01 }),
            KmipOperation.Sign);
    }

    [Fact]
    public void BuildSignRequestContainsData()
    {
        var data = new byte[] { 0xDE, 0xAD };
        var decoded = DecodeAndVerifyRequest(
            Operations.BuildSignRequest("uid-sign", data),
            KmipOperation.Sign);
        var payload = GetPayload(decoded);
        var dataItem = Ttlv.FindChild(payload, Tag.Data)!;
        Assert.Equal(data, dataItem.BytesValue);
    }

    // -----------------------------------------------------------------------
    // 26. SignatureVerify
    // -----------------------------------------------------------------------

    [Fact]
    public void BuildSignatureVerifyRequestHasCorrectOperation()
    {
        DecodeAndVerifyRequest(
            Operations.BuildSignatureVerifyRequest("uid-sv", new byte[] { 0x01 }, new byte[] { 0x02 }),
            KmipOperation.SignatureVerify);
    }

    [Fact]
    public void BuildSignatureVerifyRequestContainsDataAndSignature()
    {
        var data = new byte[] { 0xAA };
        var sig = new byte[] { 0xBB, 0xCC };
        var decoded = DecodeAndVerifyRequest(
            Operations.BuildSignatureVerifyRequest("uid-sv", data, sig),
            KmipOperation.SignatureVerify);
        var payload = GetPayload(decoded);
        var dataItem = Ttlv.FindChild(payload, Tag.Data)!;
        Assert.Equal(data, dataItem.BytesValue);
        var sigItem = Ttlv.FindChild(payload, Tag.SignatureData)!;
        Assert.Equal(sig, sigItem.BytesValue);
    }

    // -----------------------------------------------------------------------
    // 27. MAC
    // -----------------------------------------------------------------------

    [Fact]
    public void BuildMacRequestHasCorrectOperation()
    {
        DecodeAndVerifyRequest(
            Operations.BuildMacRequest("uid-mac", new byte[] { 0x01 }),
            KmipOperation.MAC);
    }

    [Fact]
    public void BuildMacRequestContainsData()
    {
        var data = new byte[] { 0xFE, 0xED };
        var decoded = DecodeAndVerifyRequest(
            Operations.BuildMacRequest("uid-mac", data),
            KmipOperation.MAC);
        var payload = GetPayload(decoded);
        var dataItem = Ttlv.FindChild(payload, Tag.Data)!;
        Assert.Equal(data, dataItem.BytesValue);
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

    // -----------------------------------------------------------------------
    // Locate payload
    // -----------------------------------------------------------------------

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

    // -----------------------------------------------------------------------
    // Get payload
    // -----------------------------------------------------------------------

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

    // -----------------------------------------------------------------------
    // Create payload
    // -----------------------------------------------------------------------

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

    // -----------------------------------------------------------------------
    // CreateKeyPair payload
    // -----------------------------------------------------------------------

    [Fact]
    public void ParseCreateKeyPairPayloadExtractsUids()
    {
        var payload = Ttlv.Decode(Ttlv.EncodeStructure(Tag.ResponsePayload,
            Ttlv.EncodeTextString(Tag.PrivateKeyUniqueIdentifier, "priv-1"),
            Ttlv.EncodeTextString(Tag.PublicKeyUniqueIdentifier, "pub-1")
        ));
        var result = Operations.ParseCreateKeyPairPayload(payload);
        Assert.Equal("priv-1", result.PrivateKeyUid);
        Assert.Equal("pub-1", result.PublicKeyUid);
    }

    // -----------------------------------------------------------------------
    // Check payload
    // -----------------------------------------------------------------------

    [Fact]
    public void ParseCheckPayloadExtractsUid()
    {
        var payload = Ttlv.Decode(Ttlv.EncodeStructure(Tag.ResponsePayload,
            Ttlv.EncodeTextString(Tag.UniqueIdentifier, "chk-uid")
        ));
        var result = Operations.ParseCheckPayload(payload);
        Assert.Equal("chk-uid", result.UniqueIdentifier);
    }

    // -----------------------------------------------------------------------
    // ReKey payload
    // -----------------------------------------------------------------------

    [Fact]
    public void ParseReKeyPayloadExtractsUid()
    {
        var payload = Ttlv.Decode(Ttlv.EncodeStructure(Tag.ResponsePayload,
            Ttlv.EncodeTextString(Tag.UniqueIdentifier, "rk-uid")
        ));
        var result = Operations.ParseReKeyPayload(payload);
        Assert.Equal("rk-uid", result.UniqueIdentifier);
    }

    // -----------------------------------------------------------------------
    // DeriveKey payload
    // -----------------------------------------------------------------------

    [Fact]
    public void ParseDeriveKeyPayloadExtractsUid()
    {
        var payload = Ttlv.Decode(Ttlv.EncodeStructure(Tag.ResponsePayload,
            Ttlv.EncodeTextString(Tag.UniqueIdentifier, "dk-uid")
        ));
        var result = Operations.ParseDeriveKeyPayload(payload);
        Assert.Equal("dk-uid", result.UniqueIdentifier);
    }

    // -----------------------------------------------------------------------
    // Encrypt payload
    // -----------------------------------------------------------------------

    [Fact]
    public void ParseEncryptPayloadExtractsDataAndNonce()
    {
        var ciphertext = new byte[] { 0xAA, 0xBB };
        var nonce = new byte[] { 0x11, 0x22, 0x33 };
        var payload = Ttlv.Decode(Ttlv.EncodeStructure(Tag.ResponsePayload,
            Ttlv.EncodeByteString(Tag.Data, ciphertext),
            Ttlv.EncodeByteString(Tag.IVCounterNonce, nonce)
        ));
        var result = Operations.ParseEncryptPayload(payload);
        Assert.Equal(ciphertext, result.Data);
        Assert.Equal(nonce, result.Nonce);
    }

    [Fact]
    public void ParseEncryptPayloadHandlesMissingNonce()
    {
        var ciphertext = new byte[] { 0xAA };
        var payload = Ttlv.Decode(Ttlv.EncodeStructure(Tag.ResponsePayload,
            Ttlv.EncodeByteString(Tag.Data, ciphertext)
        ));
        var result = Operations.ParseEncryptPayload(payload);
        Assert.Equal(ciphertext, result.Data);
        Assert.Null(result.Nonce);
    }

    // -----------------------------------------------------------------------
    // Decrypt payload
    // -----------------------------------------------------------------------

    [Fact]
    public void ParseDecryptPayloadExtractsData()
    {
        var plaintext = new byte[] { 0x01, 0x02, 0x03 };
        var payload = Ttlv.Decode(Ttlv.EncodeStructure(Tag.ResponsePayload,
            Ttlv.EncodeByteString(Tag.Data, plaintext)
        ));
        var result = Operations.ParseDecryptPayload(payload);
        Assert.Equal(plaintext, result.Data);
    }

    // -----------------------------------------------------------------------
    // Sign payload
    // -----------------------------------------------------------------------

    [Fact]
    public void ParseSignPayloadExtractsSignatureData()
    {
        var sig = new byte[] { 0xDE, 0xAD, 0xBE, 0xEF };
        var payload = Ttlv.Decode(Ttlv.EncodeStructure(Tag.ResponsePayload,
            Ttlv.EncodeByteString(Tag.SignatureData, sig)
        ));
        var result = Operations.ParseSignPayload(payload);
        Assert.Equal(sig, result.SignatureData);
    }

    // -----------------------------------------------------------------------
    // SignatureVerify payload
    // -----------------------------------------------------------------------

    [Fact]
    public void ParseSignatureVerifyPayloadReturnsTrueWhenValid()
    {
        var payload = Ttlv.Decode(Ttlv.EncodeStructure(Tag.ResponsePayload,
            Ttlv.EncodeEnum(Tag.ValidityIndicator, 0) // 0 = valid
        ));
        var result = Operations.ParseSignatureVerifyPayload(payload);
        Assert.True(result.Valid);
    }

    [Fact]
    public void ParseSignatureVerifyPayloadReturnsFalseWhenInvalid()
    {
        var payload = Ttlv.Decode(Ttlv.EncodeStructure(Tag.ResponsePayload,
            Ttlv.EncodeEnum(Tag.ValidityIndicator, 1) // 1 = invalid
        ));
        var result = Operations.ParseSignatureVerifyPayload(payload);
        Assert.False(result.Valid);
    }

    // -----------------------------------------------------------------------
    // MAC payload
    // -----------------------------------------------------------------------

    [Fact]
    public void ParseMacPayloadExtractsMacData()
    {
        var macBytes = new byte[] { 0xCA, 0xFE };
        var payload = Ttlv.Decode(Ttlv.EncodeStructure(Tag.ResponsePayload,
            Ttlv.EncodeByteString(Tag.MACData, macBytes)
        ));
        var result = Operations.ParseMacPayload(payload);
        Assert.Equal(macBytes, result.MacData);
    }

    // -----------------------------------------------------------------------
    // Query payload
    // -----------------------------------------------------------------------

    [Fact]
    public void ParseQueryPayloadExtractsOperationsAndObjectTypes()
    {
        var payload = Ttlv.Decode(Ttlv.EncodeStructure(Tag.ResponsePayload,
            Ttlv.EncodeEnum(Tag.Operation, KmipOperation.Create),
            Ttlv.EncodeEnum(Tag.Operation, KmipOperation.Get),
            Ttlv.EncodeEnum(Tag.ObjectType, KmipObjectType.SymmetricKey)
        ));
        var result = Operations.ParseQueryPayload(payload);
        Assert.Equal(2, result.Operations.Count);
        Assert.Contains(KmipOperation.Create, result.Operations);
        Assert.Contains(KmipOperation.Get, result.Operations);
        Assert.Single(result.ObjectTypes);
        Assert.Contains(KmipObjectType.SymmetricKey, result.ObjectTypes);
    }

    // -----------------------------------------------------------------------
    // DiscoverVersions payload
    // -----------------------------------------------------------------------

    [Fact]
    public void ParseDiscoverVersionsPayloadExtractsVersions()
    {
        var payload = Ttlv.Decode(Ttlv.EncodeStructure(Tag.ResponsePayload,
            Ttlv.EncodeStructure(Tag.ProtocolVersion,
                Ttlv.EncodeInteger(Tag.ProtocolVersionMajor, 1),
                Ttlv.EncodeInteger(Tag.ProtocolVersionMinor, 4)
            ),
            Ttlv.EncodeStructure(Tag.ProtocolVersion,
                Ttlv.EncodeInteger(Tag.ProtocolVersionMajor, 1),
                Ttlv.EncodeInteger(Tag.ProtocolVersionMinor, 2)
            )
        ));
        var result = Operations.ParseDiscoverVersionsPayload(payload);
        Assert.Equal(2, result.Versions.Count);
        Assert.Equal(1, result.Versions[0].Major);
        Assert.Equal(4, result.Versions[0].Minor);
        Assert.Equal(1, result.Versions[1].Major);
        Assert.Equal(2, result.Versions[1].Minor);
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

    [Theory]
    [InlineData(nameof(Operations.BuildActivateRequest), "uid-1")]
    [InlineData(nameof(Operations.BuildDestroyRequest), "uid-2")]
    [InlineData(nameof(Operations.BuildCheckRequest), "uid-3")]
    [InlineData(nameof(Operations.BuildReKeyRequest), "uid-4")]
    [InlineData(nameof(Operations.BuildArchiveRequest), "uid-5")]
    [InlineData(nameof(Operations.BuildRecoverRequest), "uid-6")]
    [InlineData(nameof(Operations.BuildObtainLeaseRequest), "uid-7")]
    [InlineData(nameof(Operations.BuildGetAttributesRequest), "uid-8")]
    [InlineData(nameof(Operations.BuildGetAttributeListRequest), "uid-9")]
    public void UidOnlyRequestsRoundTrip(string methodName, string uid)
    {
        var method = typeof(Operations).GetMethod(methodName,
            System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.Static,
            new[] { typeof(string) });
        Assert.NotNull(method);
        var request = (byte[])method!.Invoke(null, new object[] { uid })!;
        var decoded = Ttlv.Decode(request);
        Assert.Equal(Tag.RequestMessage, decoded.Tag);
        var batch = Ttlv.FindChild(decoded, Tag.BatchItem)!;
        var payload = Ttlv.FindChild(batch, Tag.RequestPayload)!;
        var uidItem = Ttlv.FindChild(payload, Tag.UniqueIdentifier)!;
        Assert.Equal(uid, uidItem.TextValue);
    }

    [Fact]
    public void EmptyPayloadRequestsRoundTrip()
    {
        foreach (var builder in new[] {
            Operations.BuildQueryRequest(),
            Operations.BuildPollRequest(),
            Operations.BuildDiscoverVersionsRequest() })
        {
            var decoded = Ttlv.Decode(builder);
            Assert.Equal(Tag.RequestMessage, decoded.Tag);
        }
    }
}

// ---------------------------------------------------------------------------
// Algorithm resolution
// ---------------------------------------------------------------------------

public class AlgorithmResolutionTests
{
    [Theory]
    [InlineData("AES", KmipAlgorithm.Aes)]
    [InlineData("aes", KmipAlgorithm.Aes)]
    [InlineData("DES", KmipAlgorithm.Des)]
    [InlineData("TRIPLEDES", KmipAlgorithm.TripleDes)]
    [InlineData("3DES", KmipAlgorithm.TripleDes)]
    [InlineData("RSA", KmipAlgorithm.Rsa)]
    [InlineData("DSA", KmipAlgorithm.Dsa)]
    [InlineData("ECDSA", KmipAlgorithm.Ecdsa)]
    [InlineData("HMACSHA1", KmipAlgorithm.HmacSha1)]
    [InlineData("HMACSHA256", KmipAlgorithm.HmacSha256)]
    [InlineData("HMACSHA384", KmipAlgorithm.HmacSha384)]
    [InlineData("HMACSHA512", KmipAlgorithm.HmacSha512)]
    public void ResolveAlgorithmReturnsCorrectValue(string name, uint expected)
    {
        Assert.Equal(expected, KmipClient.ResolveAlgorithm(name));
    }

    [Fact]
    public void ResolveAlgorithmDefaultsToAesForNull()
    {
        Assert.Equal(KmipAlgorithm.Aes, KmipClient.ResolveAlgorithm(null));
    }

    [Fact]
    public void ResolveAlgorithmDefaultsToAesForUnknown()
    {
        Assert.Equal(KmipAlgorithm.Aes, KmipClient.ResolveAlgorithm("BLOWFISH"));
    }
}
