// Copyright 2026 Horizon Digital Engineering LLC
// Licensed under the Apache License, Version 2.0

namespace Cyphera.Kmip;

/// <summary>
/// KMIP request/response builders for all 27 KMIP 1.4 operations.
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

    // -----------------------------------------------------------------------
    // Helper builders
    // -----------------------------------------------------------------------

    /// <summary>Build a request with just a UID in the payload.</summary>
    private static byte[] BuildUidOnlyRequest(uint operation, string uniqueId)
    {
        var payload = Ttlv.EncodeStructure(Tag.RequestPayload,
            Ttlv.EncodeTextString(Tag.UniqueIdentifier, uniqueId)
        );
        var batchItem = Ttlv.EncodeStructure(Tag.BatchItem,
            Ttlv.EncodeEnum(Tag.Operation, operation),
            payload
        );
        return Ttlv.EncodeStructure(Tag.RequestMessage,
            BuildRequestHeader(),
            batchItem
        );
    }

    /// <summary>Build a request with an empty payload.</summary>
    private static byte[] BuildEmptyPayloadRequest(uint operation)
    {
        var payload = Ttlv.EncodeStructure(Tag.RequestPayload);
        var batchItem = Ttlv.EncodeStructure(Tag.BatchItem,
            Ttlv.EncodeEnum(Tag.Operation, operation),
            payload
        );
        return Ttlv.EncodeStructure(Tag.RequestMessage,
            BuildRequestHeader(),
            batchItem
        );
    }

    // -----------------------------------------------------------------------
    // 1. Create
    // -----------------------------------------------------------------------

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

    // -----------------------------------------------------------------------
    // 2. CreateKeyPair
    // -----------------------------------------------------------------------

    /// <summary>Build a CreateKeyPair request.</summary>
    public static byte[] BuildCreateKeyPairRequest(string name, uint algorithm, int length)
    {
        var payload = Ttlv.EncodeStructure(Tag.RequestPayload,
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
                    Ttlv.EncodeInteger(Tag.AttributeValue, (int)(KmipUsageMask.Sign | KmipUsageMask.Verify))
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
            Ttlv.EncodeEnum(Tag.Operation, KmipOperation.CreateKeyPair),
            payload
        );
        return Ttlv.EncodeStructure(Tag.RequestMessage,
            BuildRequestHeader(),
            batchItem
        );
    }

    // -----------------------------------------------------------------------
    // 3. Register
    // -----------------------------------------------------------------------

    /// <summary>Build a Register request for a symmetric key.</summary>
    public static byte[] BuildRegisterRequest(uint objectType, byte[] material, string name, uint algorithm, int length)
    {
        var payloadChildren = new List<byte[]>
        {
            Ttlv.EncodeEnum(Tag.ObjectType, objectType),
            Ttlv.EncodeStructure(Tag.SymmetricKey,
                Ttlv.EncodeStructure(Tag.KeyBlock,
                    Ttlv.EncodeEnum(Tag.KeyFormatType, KmipKeyFormatType.Raw),
                    Ttlv.EncodeStructure(Tag.KeyValue,
                        Ttlv.EncodeByteString(Tag.KeyMaterial, material)
                    ),
                    Ttlv.EncodeEnum(Tag.CryptographicAlgorithm, algorithm),
                    Ttlv.EncodeInteger(Tag.CryptographicLength, length)
                )
            ),
        };
        if (!string.IsNullOrEmpty(name))
        {
            payloadChildren.Add(
                Ttlv.EncodeStructure(Tag.TemplateAttribute,
                    Ttlv.EncodeStructure(Tag.Attribute,
                        Ttlv.EncodeTextString(Tag.AttributeName, "Name"),
                        Ttlv.EncodeStructure(Tag.AttributeValue,
                            Ttlv.EncodeTextString(Tag.NameValue, name),
                            Ttlv.EncodeEnum(Tag.NameType, KmipNameType.UninterpretedTextString)
                        )
                    )
                )
            );
        }
        var payload = Ttlv.EncodeStructure(Tag.RequestPayload, payloadChildren.ToArray());
        var batchItem = Ttlv.EncodeStructure(Tag.BatchItem,
            Ttlv.EncodeEnum(Tag.Operation, KmipOperation.Register),
            payload
        );
        return Ttlv.EncodeStructure(Tag.RequestMessage,
            BuildRequestHeader(),
            batchItem
        );
    }

    // -----------------------------------------------------------------------
    // 4. ReKey
    // -----------------------------------------------------------------------

    /// <summary>Build a ReKey request.</summary>
    public static byte[] BuildReKeyRequest(string uniqueId) =>
        BuildUidOnlyRequest(KmipOperation.ReKey, uniqueId);

    // -----------------------------------------------------------------------
    // 5. DeriveKey
    // -----------------------------------------------------------------------

    /// <summary>Build a DeriveKey request.</summary>
    public static byte[] BuildDeriveKeyRequest(string uniqueId, byte[] derivationData, string name, int length)
    {
        var payload = Ttlv.EncodeStructure(Tag.RequestPayload,
            Ttlv.EncodeTextString(Tag.UniqueIdentifier, uniqueId),
            Ttlv.EncodeStructure(Tag.DerivationParameters,
                Ttlv.EncodeByteString(Tag.DerivationData, derivationData)
            ),
            Ttlv.EncodeStructure(Tag.TemplateAttribute,
                Ttlv.EncodeStructure(Tag.Attribute,
                    Ttlv.EncodeTextString(Tag.AttributeName, "Cryptographic Length"),
                    Ttlv.EncodeInteger(Tag.AttributeValue, length)
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
            Ttlv.EncodeEnum(Tag.Operation, KmipOperation.DeriveKey),
            payload
        );
        return Ttlv.EncodeStructure(Tag.RequestMessage,
            BuildRequestHeader(),
            batchItem
        );
    }

    // -----------------------------------------------------------------------
    // 6. Locate
    // -----------------------------------------------------------------------

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

    // -----------------------------------------------------------------------
    // 7. Check
    // -----------------------------------------------------------------------

    /// <summary>Build a Check request.</summary>
    public static byte[] BuildCheckRequest(string uniqueId) =>
        BuildUidOnlyRequest(KmipOperation.Check, uniqueId);

    // -----------------------------------------------------------------------
    // 8. Get
    // -----------------------------------------------------------------------

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

    // -----------------------------------------------------------------------
    // 9. GetAttributes
    // -----------------------------------------------------------------------

    /// <summary>Build a GetAttributes request.</summary>
    public static byte[] BuildGetAttributesRequest(string uniqueId) =>
        BuildUidOnlyRequest(KmipOperation.GetAttributes, uniqueId);

    // -----------------------------------------------------------------------
    // 10. GetAttributeList
    // -----------------------------------------------------------------------

    /// <summary>Build a GetAttributeList request.</summary>
    public static byte[] BuildGetAttributeListRequest(string uniqueId) =>
        BuildUidOnlyRequest(KmipOperation.GetAttributeList, uniqueId);

    // -----------------------------------------------------------------------
    // 11. AddAttribute
    // -----------------------------------------------------------------------

    /// <summary>Build an AddAttribute request.</summary>
    public static byte[] BuildAddAttributeRequest(string uniqueId, string attrName, string attrValue)
    {
        var payload = Ttlv.EncodeStructure(Tag.RequestPayload,
            Ttlv.EncodeTextString(Tag.UniqueIdentifier, uniqueId),
            Ttlv.EncodeStructure(Tag.Attribute,
                Ttlv.EncodeTextString(Tag.AttributeName, attrName),
                Ttlv.EncodeTextString(Tag.AttributeValue, attrValue)
            )
        );
        var batchItem = Ttlv.EncodeStructure(Tag.BatchItem,
            Ttlv.EncodeEnum(Tag.Operation, KmipOperation.AddAttribute),
            payload
        );
        return Ttlv.EncodeStructure(Tag.RequestMessage,
            BuildRequestHeader(),
            batchItem
        );
    }

    // -----------------------------------------------------------------------
    // 12. ModifyAttribute
    // -----------------------------------------------------------------------

    /// <summary>Build a ModifyAttribute request.</summary>
    public static byte[] BuildModifyAttributeRequest(string uniqueId, string attrName, string attrValue)
    {
        var payload = Ttlv.EncodeStructure(Tag.RequestPayload,
            Ttlv.EncodeTextString(Tag.UniqueIdentifier, uniqueId),
            Ttlv.EncodeStructure(Tag.Attribute,
                Ttlv.EncodeTextString(Tag.AttributeName, attrName),
                Ttlv.EncodeTextString(Tag.AttributeValue, attrValue)
            )
        );
        var batchItem = Ttlv.EncodeStructure(Tag.BatchItem,
            Ttlv.EncodeEnum(Tag.Operation, KmipOperation.ModifyAttribute),
            payload
        );
        return Ttlv.EncodeStructure(Tag.RequestMessage,
            BuildRequestHeader(),
            batchItem
        );
    }

    // -----------------------------------------------------------------------
    // 13. DeleteAttribute
    // -----------------------------------------------------------------------

    /// <summary>Build a DeleteAttribute request.</summary>
    public static byte[] BuildDeleteAttributeRequest(string uniqueId, string attrName)
    {
        var payload = Ttlv.EncodeStructure(Tag.RequestPayload,
            Ttlv.EncodeTextString(Tag.UniqueIdentifier, uniqueId),
            Ttlv.EncodeStructure(Tag.Attribute,
                Ttlv.EncodeTextString(Tag.AttributeName, attrName)
            )
        );
        var batchItem = Ttlv.EncodeStructure(Tag.BatchItem,
            Ttlv.EncodeEnum(Tag.Operation, KmipOperation.DeleteAttribute),
            payload
        );
        return Ttlv.EncodeStructure(Tag.RequestMessage,
            BuildRequestHeader(),
            batchItem
        );
    }

    // -----------------------------------------------------------------------
    // 14. ObtainLease
    // -----------------------------------------------------------------------

    /// <summary>Build an ObtainLease request.</summary>
    public static byte[] BuildObtainLeaseRequest(string uniqueId) =>
        BuildUidOnlyRequest(KmipOperation.ObtainLease, uniqueId);

    // -----------------------------------------------------------------------
    // 15. Activate
    // -----------------------------------------------------------------------

    /// <summary>Build an Activate request for a key by unique ID.</summary>
    public static byte[] BuildActivateRequest(string uniqueId) =>
        BuildUidOnlyRequest(KmipOperation.Activate, uniqueId);

    // -----------------------------------------------------------------------
    // 16. Revoke
    // -----------------------------------------------------------------------

    /// <summary>Build a Revoke request with a revocation reason.</summary>
    public static byte[] BuildRevokeRequest(string uniqueId, uint reason)
    {
        var payload = Ttlv.EncodeStructure(Tag.RequestPayload,
            Ttlv.EncodeTextString(Tag.UniqueIdentifier, uniqueId),
            Ttlv.EncodeStructure(Tag.RevocationReason,
                Ttlv.EncodeEnum(Tag.RevocationReasonCode, reason)
            )
        );
        var batchItem = Ttlv.EncodeStructure(Tag.BatchItem,
            Ttlv.EncodeEnum(Tag.Operation, KmipOperation.Revoke),
            payload
        );
        return Ttlv.EncodeStructure(Tag.RequestMessage,
            BuildRequestHeader(),
            batchItem
        );
    }

    // -----------------------------------------------------------------------
    // 17. Destroy
    // -----------------------------------------------------------------------

    /// <summary>Build a Destroy request for a key by unique ID.</summary>
    public static byte[] BuildDestroyRequest(string uniqueId) =>
        BuildUidOnlyRequest(KmipOperation.Destroy, uniqueId);

    // -----------------------------------------------------------------------
    // 18. Archive
    // -----------------------------------------------------------------------

    /// <summary>Build an Archive request.</summary>
    public static byte[] BuildArchiveRequest(string uniqueId) =>
        BuildUidOnlyRequest(KmipOperation.Archive, uniqueId);

    // -----------------------------------------------------------------------
    // 19. Recover
    // -----------------------------------------------------------------------

    /// <summary>Build a Recover request.</summary>
    public static byte[] BuildRecoverRequest(string uniqueId) =>
        BuildUidOnlyRequest(KmipOperation.Recover, uniqueId);

    // -----------------------------------------------------------------------
    // 20. Query
    // -----------------------------------------------------------------------

    /// <summary>Build a Query request.</summary>
    public static byte[] BuildQueryRequest() =>
        BuildEmptyPayloadRequest(KmipOperation.Query);

    // -----------------------------------------------------------------------
    // 21. Poll
    // -----------------------------------------------------------------------

    /// <summary>Build a Poll request.</summary>
    public static byte[] BuildPollRequest() =>
        BuildEmptyPayloadRequest(KmipOperation.Poll);

    // -----------------------------------------------------------------------
    // 22. DiscoverVersions
    // -----------------------------------------------------------------------

    /// <summary>Build a DiscoverVersions request.</summary>
    public static byte[] BuildDiscoverVersionsRequest() =>
        BuildEmptyPayloadRequest(KmipOperation.DiscoverVersions);

    // -----------------------------------------------------------------------
    // 23. Encrypt
    // -----------------------------------------------------------------------

    /// <summary>Build an Encrypt request.</summary>
    public static byte[] BuildEncryptRequest(string uniqueId, byte[] data)
    {
        var payload = Ttlv.EncodeStructure(Tag.RequestPayload,
            Ttlv.EncodeTextString(Tag.UniqueIdentifier, uniqueId),
            Ttlv.EncodeByteString(Tag.Data, data)
        );
        var batchItem = Ttlv.EncodeStructure(Tag.BatchItem,
            Ttlv.EncodeEnum(Tag.Operation, KmipOperation.Encrypt),
            payload
        );
        return Ttlv.EncodeStructure(Tag.RequestMessage,
            BuildRequestHeader(),
            batchItem
        );
    }

    // -----------------------------------------------------------------------
    // 24. Decrypt
    // -----------------------------------------------------------------------

    /// <summary>Build a Decrypt request.</summary>
    public static byte[] BuildDecryptRequest(string uniqueId, byte[] data, byte[]? nonce = null)
    {
        var payloadChildren = new List<byte[]>
        {
            Ttlv.EncodeTextString(Tag.UniqueIdentifier, uniqueId),
            Ttlv.EncodeByteString(Tag.Data, data),
        };
        if (nonce != null && nonce.Length > 0)
        {
            payloadChildren.Add(Ttlv.EncodeByteString(Tag.IVCounterNonce, nonce));
        }
        var payload = Ttlv.EncodeStructure(Tag.RequestPayload, payloadChildren.ToArray());
        var batchItem = Ttlv.EncodeStructure(Tag.BatchItem,
            Ttlv.EncodeEnum(Tag.Operation, KmipOperation.Decrypt),
            payload
        );
        return Ttlv.EncodeStructure(Tag.RequestMessage,
            BuildRequestHeader(),
            batchItem
        );
    }

    // -----------------------------------------------------------------------
    // 25. Sign
    // -----------------------------------------------------------------------

    /// <summary>Build a Sign request.</summary>
    public static byte[] BuildSignRequest(string uniqueId, byte[] data)
    {
        var payload = Ttlv.EncodeStructure(Tag.RequestPayload,
            Ttlv.EncodeTextString(Tag.UniqueIdentifier, uniqueId),
            Ttlv.EncodeByteString(Tag.Data, data)
        );
        var batchItem = Ttlv.EncodeStructure(Tag.BatchItem,
            Ttlv.EncodeEnum(Tag.Operation, KmipOperation.Sign),
            payload
        );
        return Ttlv.EncodeStructure(Tag.RequestMessage,
            BuildRequestHeader(),
            batchItem
        );
    }

    // -----------------------------------------------------------------------
    // 26. SignatureVerify
    // -----------------------------------------------------------------------

    /// <summary>Build a SignatureVerify request.</summary>
    public static byte[] BuildSignatureVerifyRequest(string uniqueId, byte[] data, byte[] signature)
    {
        var payload = Ttlv.EncodeStructure(Tag.RequestPayload,
            Ttlv.EncodeTextString(Tag.UniqueIdentifier, uniqueId),
            Ttlv.EncodeByteString(Tag.Data, data),
            Ttlv.EncodeByteString(Tag.SignatureData, signature)
        );
        var batchItem = Ttlv.EncodeStructure(Tag.BatchItem,
            Ttlv.EncodeEnum(Tag.Operation, KmipOperation.SignatureVerify),
            payload
        );
        return Ttlv.EncodeStructure(Tag.RequestMessage,
            BuildRequestHeader(),
            batchItem
        );
    }

    // -----------------------------------------------------------------------
    // 27. MAC
    // -----------------------------------------------------------------------

    /// <summary>Build a MAC request.</summary>
    public static byte[] BuildMacRequest(string uniqueId, byte[] data)
    {
        var payload = Ttlv.EncodeStructure(Tag.RequestPayload,
            Ttlv.EncodeTextString(Tag.UniqueIdentifier, uniqueId),
            Ttlv.EncodeByteString(Tag.Data, data)
        );
        var batchItem = Ttlv.EncodeStructure(Tag.BatchItem,
            Ttlv.EncodeEnum(Tag.Operation, KmipOperation.MAC),
            payload
        );
        return Ttlv.EncodeStructure(Tag.RequestMessage,
            BuildRequestHeader(),
            batchItem
        );
    }

    // -----------------------------------------------------------------------
    // Response parsing
    // -----------------------------------------------------------------------

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

    /// <summary>Parse a CreateKeyPair response payload.</summary>
    public static CreateKeyPairResult ParseCreateKeyPairPayload(TtlvItem payload)
    {
        var privUid = Ttlv.FindChild(payload, Tag.PrivateKeyUniqueIdentifier);
        var pubUid = Ttlv.FindChild(payload, Tag.PublicKeyUniqueIdentifier);
        return new CreateKeyPairResult
        {
            PrivateKeyUid = privUid?.TextValue,
            PublicKeyUid = pubUid?.TextValue,
        };
    }

    /// <summary>Parse a Check response payload.</summary>
    public static CheckResult ParseCheckPayload(TtlvItem payload)
    {
        var uid = Ttlv.FindChild(payload, Tag.UniqueIdentifier);
        return new CheckResult
        {
            UniqueIdentifier = uid?.TextValue,
        };
    }

    /// <summary>Parse a ReKey response payload.</summary>
    public static ReKeyResult ParseReKeyPayload(TtlvItem payload)
    {
        var uid = Ttlv.FindChild(payload, Tag.UniqueIdentifier);
        return new ReKeyResult
        {
            UniqueIdentifier = uid?.TextValue,
        };
    }

    /// <summary>Parse a DeriveKey response payload.</summary>
    public static DeriveKeyResult ParseDeriveKeyPayload(TtlvItem payload)
    {
        var uid = Ttlv.FindChild(payload, Tag.UniqueIdentifier);
        return new DeriveKeyResult
        {
            UniqueIdentifier = uid?.TextValue,
        };
    }

    /// <summary>Parse an Encrypt response payload.</summary>
    public static EncryptResult ParseEncryptPayload(TtlvItem payload)
    {
        var data = Ttlv.FindChild(payload, Tag.Data);
        var nonce = Ttlv.FindChild(payload, Tag.IVCounterNonce);
        return new EncryptResult
        {
            Data = data?.BytesValue,
            Nonce = nonce?.BytesValue,
        };
    }

    /// <summary>Parse a Decrypt response payload.</summary>
    public static DecryptResult ParseDecryptPayload(TtlvItem payload)
    {
        var data = Ttlv.FindChild(payload, Tag.Data);
        return new DecryptResult
        {
            Data = data?.BytesValue,
        };
    }

    /// <summary>Parse a Sign response payload.</summary>
    public static SignResult ParseSignPayload(TtlvItem payload)
    {
        var sig = Ttlv.FindChild(payload, Tag.SignatureData);
        return new SignResult
        {
            SignatureData = sig?.BytesValue,
        };
    }

    /// <summary>Parse a SignatureVerify response payload.</summary>
    public static SignatureVerifyResult ParseSignatureVerifyPayload(TtlvItem payload)
    {
        var indicator = Ttlv.FindChild(payload, Tag.ValidityIndicator);
        return new SignatureVerifyResult
        {
            // 0 = Valid, 1 = Invalid
            Valid = indicator != null && indicator.EnumValue == 0,
        };
    }

    /// <summary>Parse a MAC response payload.</summary>
    public static MacResult ParseMacPayload(TtlvItem payload)
    {
        var macData = Ttlv.FindChild(payload, Tag.MACData);
        return new MacResult
        {
            MacData = macData?.BytesValue,
        };
    }

    /// <summary>Parse a Query response payload.</summary>
    public static QueryResult ParseQueryPayload(TtlvItem payload)
    {
        var ops = Ttlv.FindChildren(payload, Tag.Operation);
        var objTypes = Ttlv.FindChildren(payload, Tag.ObjectType);
        return new QueryResult
        {
            Operations = ops.Select(o => o.EnumValue).ToList(),
            ObjectTypes = objTypes.Select(o => o.EnumValue).ToList(),
        };
    }

    /// <summary>Parse a DiscoverVersions response payload.</summary>
    public static DiscoverVersionsResult ParseDiscoverVersionsPayload(TtlvItem payload)
    {
        var versions = Ttlv.FindChildren(payload, Tag.ProtocolVersion);
        var result = new DiscoverVersionsResult();
        foreach (var v in versions)
        {
            var major = Ttlv.FindChild(v, Tag.ProtocolVersionMajor);
            var minor = Ttlv.FindChild(v, Tag.ProtocolVersionMinor);
            result.Versions.Add(new ProtocolVersionEntry
            {
                Major = major?.IntegerValue ?? 0,
                Minor = minor?.IntegerValue ?? 0,
            });
        }
        return result;
    }
}

// ---------------------------------------------------------------------------
// Response / result types
// ---------------------------------------------------------------------------

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

/// <summary>Parsed CreateKeyPair response.</summary>
public sealed class CreateKeyPairResult
{
    public string? PrivateKeyUid { get; init; }
    public string? PublicKeyUid { get; init; }
}

/// <summary>Parsed Check response.</summary>
public sealed class CheckResult
{
    public string? UniqueIdentifier { get; init; }
}

/// <summary>Parsed ReKey response.</summary>
public sealed class ReKeyResult
{
    public string? UniqueIdentifier { get; init; }
}

/// <summary>Parsed DeriveKey response.</summary>
public sealed class DeriveKeyResult
{
    public string? UniqueIdentifier { get; init; }
}

/// <summary>Parsed Encrypt response.</summary>
public sealed class EncryptResult
{
    public byte[]? Data { get; init; }
    public byte[]? Nonce { get; init; }
}

/// <summary>Parsed Decrypt response.</summary>
public sealed class DecryptResult
{
    public byte[]? Data { get; init; }
}

/// <summary>Parsed Sign response.</summary>
public sealed class SignResult
{
    public byte[]? SignatureData { get; init; }
}

/// <summary>Parsed SignatureVerify response.</summary>
public sealed class SignatureVerifyResult
{
    public bool Valid { get; init; }
}

/// <summary>Parsed MAC response.</summary>
public sealed class MacResult
{
    public byte[]? MacData { get; init; }
}

/// <summary>Parsed Query response.</summary>
public sealed class QueryResult
{
    public List<uint> Operations { get; init; } = new();
    public List<uint> ObjectTypes { get; init; } = new();
}

/// <summary>Parsed DiscoverVersions response.</summary>
public sealed class DiscoverVersionsResult
{
    public List<ProtocolVersionEntry> Versions { get; init; } = new();
}

/// <summary>A protocol version entry (major.minor).</summary>
public sealed class ProtocolVersionEntry
{
    public int Major { get; init; }
    public int Minor { get; init; }
}

/// <summary>KMIP operation exception.</summary>
public sealed class KmipException : Exception
{
    public uint? ResultStatus { get; init; }
    public uint? ResultReason { get; init; }

    public KmipException(string message) : base(message) { }
    public KmipException(string message, Exception inner) : base(message, inner) { }
}
