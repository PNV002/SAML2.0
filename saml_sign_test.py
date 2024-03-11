import xmlsec
from lxml import etree

def validate_saml_signature(xml_response, certificate_file):
    # Load the SAML response XML
    xml_tree = etree.fromstring(xml_response)

    # Load the certificate
    key = xmlsec.Key.from_file(certificate_file, xmlsec.KeyFormat.CERT_PEM)

    # Create a signature context
    signature_ctx = xmlsec.SignatureContext()

    # Load the XML data into the context
    signature_ctx.load_xml(xml_tree)

    # Verify the signature
    result = signature_ctx.verify(key)

    return result

# Example usage
xml_response = """
    <saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:xs="http://www.w3.org/2001/XMLSchema" Destination="http://localhost:5000/user/saml/login" ID="id3727707389877221841789451" IssueInstant="2024-03-01T10:35:53.697Z" Version="2.0">
<saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">http://www.okta.com/exkf8znpymURITvYu5d7</saml2:Issuer>
<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
<ds:SignedInfo>
<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
<ds:Reference URI="#id3727707389877221841789451">
<ds:Transforms>
<ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
<ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#">
<ec:InclusiveNamespaces xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#" PrefixList="xs"/>
</ds:Transform>
</ds:Transforms>
<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
<ds:DigestValue>h82zD0J+Y8OTGFPtJycnrrS0+u27wCmUahEtwELPpVQ=</ds:DigestValue>
</ds:Reference>
</ds:SignedInfo>
<ds:SignatureValue>kgb+6xRpWTPZ48HN9OpmWdw40Hx5KgItiTENQoiJP/jUStM0q2OfAvhLEby25XqBQSW8UvdFb8wlIwMmiJBTQWtG22FDIAEsW6OHvpqqtrZtqUj0nuaGOQCOKUseAz+wtYKlG5tfu5FVEY2vMxsWGCY1yWAjDbtCYoo8W0NePZ1F+G4HZa/ICOWOWwY8iPnVCbbJk8cCGjg59kfnRY45WJdsEuJw5gJi/dc1sVVirIi5gSAryAOiKNIMQKFcxQgKgNZ56QLmbP3ig3EsxniyfNJlno3TezvM3zmMCsc2yq7XqnbfhpQHtJWnQw+Ys5Gx9kF63k4EpxxGEdp+zG0H1g==</ds:SignatureValue>
<ds:KeyInfo>
<ds:X509Data>
<ds:X509Certificate>MIIDqDCCApCgAwIBAgIGAY3ulIEgMA0GCSqGSIb3DQEBCwUAMIGUMQswCQYDVQQGEwJVUzETMBEG A1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNU2FuIEZyYW5jaXNjbzENMAsGA1UECgwET2t0YTEU MBIGA1UECwwLU1NPUHJvdmlkZXIxFTATBgNVBAMMDGRldi0xODYxNTAzMDEcMBoGCSqGSIb3DQEJ ARYNaW5mb0Bva3RhLmNvbTAeFw0yNDAyMjgwNzE3NDZaFw0zNDAyMjgwNzE4NDZaMIGUMQswCQYD VQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNU2FuIEZyYW5jaXNjbzENMAsG A1UECgwET2t0YTEUMBIGA1UECwwLU1NPUHJvdmlkZXIxFTATBgNVBAMMDGRldi0xODYxNTAzMDEc MBoGCSqGSIb3DQEJARYNaW5mb0Bva3RhLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC ggEBAKQGnqw44w5xdT2iAtvKahLqwU/l+9Cu13sb44/SHD80ULY5ABDprMgZBYFulHhNnAxvV5wJ NR7dnVdlZjV/yGd4qv5axUdWqkKAZ8g2GDQytB8dexOF4e6FPxQNtE5tLUMAQJSOE92/GVp8NooK 9Wt4pj/9NF4UY2sx+iO+CH+nLQpC+cD6eB54v85GZ8Sp00YT+xrC/1900ZitLKjXdx1BVETvAFu6 Yon2NWVAuDvM30Q2h6I6e8RHW1XAZGVoInUumaN9pA4T7ZOHqmeidQCzwlXNrHp2yhCGlxmOfhqn BjmEwTsJ1lS6ST8R+0DVKr0K05TZNyB55Bb7KG27ZGMCAwEAATANBgkqhkiG9w0BAQsFAAOCAQEA ZczXr+NHEGZoDw5QCXlvADhsNa2yd+B/GOfIadzSZZ8ZdGL2Ec6xPA5gl2jMHtrSFDuFPBB5Q6wO Z1+BM0kLvp2shl2wmqlhWU3zFCjizcmd+NaTjis0O4XJbMhusRvWxQlswE1ZcSVLcuEPfLgaLWWm LENLOdHTLiufpibdN2/cuJDQPj3O6jrSZRmU2/5xZoz7sSfVzTFLqOCiwNvjnQGlgraHO3PwFMyv kz8SL5DGSKrGkQFjCk9pDP7pxX/nNRGnqkHN5f30LTuNwMbcK/kbsjpVrM3uewckIGNUcqc8QxRJ phVrZs26VYTh2xAXqz9/wNwrN1YL7CWA7a9lsA==</ds:X509Certificate>
</ds:X509Data>
</ds:KeyInfo>
</ds:Signature>
<saml2p:Status xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol">
<saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
</saml2p:Status>
<saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:xs="http://www.w3.org/2001/XMLSchema" ID="id3727707391514852077927452" IssueInstant="2024-03-01T10:35:53.697Z" Version="2.0">
<saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">http://www.okta.com/exkf8znpymURITvYu5d7</saml2:Issuer>
<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
<ds:SignedInfo>
<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
<ds:Reference URI="#id3727707391514852077927452">
<ds:Transforms>
<ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
<ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#">
<ec:InclusiveNamespaces xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#" PrefixList="xs"/>
</ds:Transform>
</ds:Transforms>
<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
<ds:DigestValue>Wfg1VvnGSj3bYru4YEIzSUjR3JUlwdogpBd5YjseALc=</ds:DigestValue>
</ds:Reference>
</ds:SignedInfo>
<ds:SignatureValue>T306gG4P7Kc05xxQOCoPZLxKGavk18qjd/AikYLq/aiizoA0qQx883ZAjEIsnfdkIjdXF7NafMtAXv2rxC9zprxDvt1Bsv/Sf2bpLAeEIVarV4r9EYJAxGBUqzScFY4PzFPdYUwAxsoypOhTfw1LM5vC22SUDnkN/VimL+cWEFyAVVKQ92DH5TQ3Iwd/npcuk73gH+DUBbfq8gVzA7R6ltypxv48wiJWifenw/RR4jCYwfm/cJ4RzKL4tml09eXpzwId7sk3A3Y5clcznMJh/LnDe98cdkIFKqSE90CBhx+2fDwN/bPRtzzCtJVnJrwPdOqLPbxIT7tmTOg1xDLYfg==</ds:SignatureValue>
<ds:KeyInfo>
<ds:X509Data>
<ds:X509Certificate>MIIDqDCCApCgAwIBAgIGAY3ulIEgMA0GCSqGSIb3DQEBCwUAMIGUMQswCQYDVQQGEwJVUzETMBEG A1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNU2FuIEZyYW5jaXNjbzENMAsGA1UECgwET2t0YTEU MBIGA1UECwwLU1NPUHJvdmlkZXIxFTATBgNVBAMMDGRldi0xODYxNTAzMDEcMBoGCSqGSIb3DQEJ ARYNaW5mb0Bva3RhLmNvbTAeFw0yNDAyMjgwNzE3NDZaFw0zNDAyMjgwNzE4NDZaMIGUMQswCQYD VQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNU2FuIEZyYW5jaXNjbzENMAsG A1UECgwET2t0YTEUMBIGA1UECwwLU1NPUHJvdmlkZXIxFTATBgNVBAMMDGRldi0xODYxNTAzMDEc MBoGCSqGSIb3DQEJARYNaW5mb0Bva3RhLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC ggEBAKQGnqw44w5xdT2iAtvKahLqwU/l+9Cu13sb44/SHD80ULY5ABDprMgZBYFulHhNnAxvV5wJ NR7dnVdlZjV/yGd4qv5axUdWqkKAZ8g2GDQytB8dexOF4e6FPxQNtE5tLUMAQJSOE92/GVp8NooK 9Wt4pj/9NF4UY2sx+iO+CH+nLQpC+cD6eB54v85GZ8Sp00YT+xrC/1900ZitLKjXdx1BVETvAFu6 Yon2NWVAuDvM30Q2h6I6e8RHW1XAZGVoInUumaN9pA4T7ZOHqmeidQCzwlXNrHp2yhCGlxmOfhqn BjmEwTsJ1lS6ST8R+0DVKr0K05TZNyB55Bb7KG27ZGMCAwEAATANBgkqhkiG9w0BAQsFAAOCAQEA ZczXr+NHEGZoDw5QCXlvADhsNa2yd+B/GOfIadzSZZ8ZdGL2Ec6xPA5gl2jMHtrSFDuFPBB5Q6wO Z1+BM0kLvp2shl2wmqlhWU3zFCjizcmd+NaTjis0O4XJbMhusRvWxQlswE1ZcSVLcuEPfLgaLWWm LENLOdHTLiufpibdN2/cuJDQPj3O6jrSZRmU2/5xZoz7sSfVzTFLqOCiwNvjnQGlgraHO3PwFMyv kz8SL5DGSKrGkQFjCk9pDP7pxX/nNRGnqkHN5f30LTuNwMbcK/kbsjpVrM3uewckIGNUcqc8QxRJ phVrZs26VYTh2xAXqz9/wNwrN1YL7CWA7a9lsA==</ds:X509Certificate>
</ds:X509Data>
</ds:KeyInfo>
</ds:Signature>
<saml2:Subject xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">
<saml2:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">pranavi.20bcr7011@vitap.ac.in</saml2:NameID>
<saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
<saml2:SubjectConfirmationData NotOnOrAfter="2024-03-01T10:40:53.697Z" Recipient="http://localhost:5000/user/saml/login"/>
</saml2:SubjectConfirmation>
</saml2:Subject>
<saml2:Conditions xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" NotBefore="2024-03-01T10:30:53.697Z" NotOnOrAfter="2024-03-01T10:40:53.697Z">
<saml2:AudienceRestriction>
<saml2:Audience>http://localhost:5000/user/saml/login</saml2:Audience>
</saml2:AudienceRestriction>
</saml2:Conditions>
<saml2:AuthnStatement xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" AuthnInstant="2024-03-01T10:35:53.697Z" SessionIndex="id1709289353502.297557055">
<saml2:AuthnContext>
<saml2:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml2:AuthnContextClassRef>
</saml2:AuthnContext>
</saml2:AuthnStatement>
<saml2:AttributeStatement xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">
<saml2:Attribute Name="Email" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified">
<saml2:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">pranavi.20bcr7011@vitap.ac.in</saml2:AttributeValue>
</saml2:Attribute>
<saml2:Attribute Name="Password" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified">
<saml2:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string"/>
</saml2:Attribute>
</saml2:AttributeStatement>
</saml2:Assertion>
</saml2p:Response>
"""

certificate_file = "okta.cert"  # Path to the X.509 certificate file

is_valid = validate_saml_signature(xml_response, certificate_file)
print("Is signature valid?", is_valid)
