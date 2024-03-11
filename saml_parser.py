import xml.etree.ElementTree as ET

# Register namespaces
ET.register_namespace('saml2p', 'urn:oasis:names:tc:SAML:2.0:protocol')
ET.register_namespace('saml2', 'urn:oasis:names:tc:SAML:2.0:assertion')
ET.register_namespace('ds', 'http://www.w3.org/2000/09/xmldsig#')
ET.register_namespace('ec', 'http://www.w3.org/2001/10/xml-exc-c14n#')

saml_response = """
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
                 xmlns:xs="http://www.w3.org/2001/XMLSchema"
                 Destination="http://localhost:5000/user/saml/login"
                 ID="id14067592677663692144235827"
                 IssueInstant="2024-03-06T09:48:59.266Z"
                 Version="2.0"
                 >
    <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"
                  Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity"
                  >http://www.okta.com/exkf8znpymURITvYu5d7</saml2:Issuer>
    <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <ds:SignedInfo>
            <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#" />
            <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" />
            <ds:Reference URI="#id14067592677663692144235827">
                <ds:Transforms>
                    <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature" />
                    <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#">
                        <ec:InclusiveNamespaces xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#"
                                                PrefixList="xs"
                                                />
                    </ds:Transform>
                </ds:Transforms>
                <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256" />
                <ds:DigestValue>6l1moaj/rKgNSMq/tfRWMNZtnf62QavUo8iypsy0vL4=</ds:DigestValue>
            </ds:Reference>
        </ds:SignedInfo>
        <ds:SignatureValue>ikWIgb7lp650rRixy6X2ph2l+vdUnCadEcJ2pvG5eV6NesCbpgtRFJmxTRRDRycjoDGV8O/ZVrJLCURHJMlnvWwFZYQpGUQyVgqtWUwH5cGRR2OPCqtel7Za+bvAQs+hxW23/IQmBRBMIQdgWq9F+QNztLJIumpBlU1O5SyY3VYxjVLMaBb7V3FvUzyN5CrWKFRL2IZdbDDdms4WTOvNPQ9nDd6OEtkuU73/kx18o60FIPOoG2mlcxbbtyg5W9j4af8g7nPYr7Umr6WxK9kiAA7QJ954p2s4QDfYvpOuLs6hXhbReg4tAWGlrBl2mrMWMoW5ZanQeoeabq63ANtECg==</ds:SignatureValue>
        <ds:KeyInfo>
            <ds:X509Data>
                <ds:X509Certificate>MIIDqDCCApCgAwIBAgIGAY3ulIEgMA0GCSqGSIb3DQEBCwUAMIGUMQswCQYDVQQGEwJVUzETMBEG
A1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNU2FuIEZyYW5jaXNjbzENMAsGA1UECgwET2t0YTEU
MBIGA1UECwwLU1NPUHJvdmlkZXIxFTATBgNVBAMMDGRldi0xODYxNTAzMDEcMBoGCSqGSIb3DQEJ
ARYNaW5mb0Bva3RhLmNvbTAeFw0yNDAyMjgwNzE3NDZaFw0zNDAyMjgwNzE4NDZaMIGUMQswCQYD
VQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNU2FuIEZyYW5jaXNjbzENMAsG
A1UECgwET2t0YTEUMBIGA1UECwwLU1NPUHJvdmlkZXIxFTATBgNVBAMMDGRldi0xODYxNTAzMDEc
MBoGCSqGSIb3DQEJARYNaW5mb0Bva3RhLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC
ggEBAKQGnqw44w5xdT2iAtvKahLqwU/l+9Cu13sb44/SHD80ULY5ABDprMgZBYFulHhNnAxvV5wJ
NR7dnVdlZjV/yGd4qv5axUdWqkKAZ8g2GDQytB8dexOF4e6FPxQNtE5tLUMAQJSOE92/GVp8NooK
9Wt4pj/9NF4UY2sx+iO+CH+nLQpC+cD6eB54v85GZ8Sp00YT+xrC/1900ZitLKjXdx1BVETvAFu6
Yon2NWVAuDvM30Q2h6I6e8RHW1XAZGVoInUumaN9pA4T7ZOHqmeidQCzwlXNrHp2yhCGlxmOfhqn
BjmEwTsJ1lS6ST8R+0DVKr0K05TZNyB55Bb7KG27ZGMCAwEAATANBgkqhkiG9w0BAQsFAAOCAQEA
ZczXr+NHEGZoDw5QCXlvADhsNa2yd+B/GOfIadzSZZ8ZdGL2Ec6xPA5gl2jMHtrSFDuFPBB5Q6wO
Z1+BM0kLvp2shl2wmqlhWU3zFCjizcmd+NaTjis0O4XJbMhusRvWxQlswE1ZcSVLcuEPfLgaLWWm
LENLOdHTLiufpibdN2/cuJDQPj3O6jrSZRmU2/5xZoz7sSfVzTFLqOCiwNvjnQGlgraHO3PwFMyv
kz8SL5DGSKrGkQFjCk9pDP7pxX/nNRGnqkHN5f30LTuNwMbcK/kbsjpVrM3uewckIGNUcqc8QxRJ
phVrZs26VYTh2xAXqz9/wNwrN1YL7CWA7a9lsA==</ds:X509Certificate>
            </ds:X509Data>
        </ds:KeyInfo>
    </ds:Signature>
    <saml2p:Status xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol">
        <saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success" />
    </saml2p:Status>
    <saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"
                     xmlns:xs="http://www.w3.org/2001/XMLSchema"
                     ID="id14067592681683541417062328"
                     IssueInstant="2024-03-06T09:48:59.266Z"
                     Version="2.0"
                     >
        <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"
                      Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity"
                      >http://www.okta.com/exkf8znpymURITvYu5d7</saml2:Issuer>
        <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
            <ds:SignedInfo>
                <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#" />
                <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" />
                <ds:Reference URI="#id14067592681683541417062328">
                    <ds:Transforms>
                        <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature" />
                        <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#">
                            <ec:InclusiveNamespaces xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#"
                                                    PrefixList="xs"
                                                    />
                        </ds:Transform>
                    </ds:Transforms>
                    <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256" />
                    <ds:DigestValue>aDcrs2reCoVDLNK/0vqRGv4QXNWkWAEghVCYNogGczo=</ds:DigestValue>
                </ds:Reference>
            </ds:SignedInfo>
            <ds:SignatureValue>jwX42H25KYDtVlQUlU2lgK8W+RIVtusEncD/aSg/BDLtKscEGUTA3S6vmpmd4NkTn7Pzq/z0TqL8NBYPGEUhfvBr//aLFI6EScr4VilSMKTc1dmXIN6bj+BiYNe79jG2X65EBOCCYe+3faxxlILuW9sdqxSWe18IxnuUjKambhvktwSEyVFRbNDC9wVYenAC5hr54WDCzRpcLvwxkTUepM3UCTCLe6RMaIaB4y7JsFwZnsUyhzrcMm5yFkk0DgA10oKyZ/jStdmVeCDYHE9TVj6mq3B/molAf/MMV1JtBJA/MudkyNIXWBGfMD4oGv3reYV0K+ieRPm/MP06//OFaA==</ds:SignatureValue>
            <ds:KeyInfo>
                <ds:X509Data>
                    <ds:X509Certificate>MIIDqDCCApCgAwIBAgIGAY3ulIEgMA0GCSqGSIb3DQEBCwUAMIGUMQswCQYDVQQGEwJVUzETMBEG
A1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNU2FuIEZyYW5jaXNjbzENMAsGA1UECgwET2t0YTEU
MBIGA1UECwwLU1NPUHJvdmlkZXIxFTATBgNVBAMMDGRldi0xODYxNTAzMDEcMBoGCSqGSIb3DQEJ
ARYNaW5mb0Bva3RhLmNvbTAeFw0yNDAyMjgwNzE3NDZaFw0zNDAyMjgwNzE4NDZaMIGUMQswCQYD
VQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNU2FuIEZyYW5jaXNjbzENMAsG
A1UECgwET2t0YTEUMBIGA1UECwwLU1NPUHJvdmlkZXIxFTATBgNVBAMMDGRldi0xODYxNTAzMDEc
MBoGCSqGSIb3DQEJARYNaW5mb0Bva3RhLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC
ggEBAKQGnqw44w5xdT2iAtvKahLqwU/l+9Cu13sb44/SHD80ULY5ABDprMgZBYFulHhNnAxvV5wJ
NR7dnVdlZjV/yGd4qv5axUdWqkKAZ8g2GDQytB8dexOF4e6FPxQNtE5tLUMAQJSOE92/GVp8NooK
9Wt4pj/9NF4UY2sx+iO+CH+nLQpC+cD6eB54v85GZ8Sp00YT+xrC/1900ZitLKjXdx1BVETvAFu6
Yon2NWVAuDvM30Q2h6I6e8RHW1XAZGVoInUumaN9pA4T7ZOHqmeidQCzwlXNrHp2yhCGlxmOfhqn
BjmEwTsJ1lS6ST8R+0DVKr0K05TZNyB55Bb7KG27ZGMCAwEAATANBgkqhkiG9w0BAQsFAAOCAQEA
ZczXr+NHEGZoDw5QCXlvADhsNa2yd+B/GOfIadzSZZ8ZdGL2Ec6xPA5gl2jMHtrSFDuFPBB5Q6wO
Z1+BM0kLvp2shl2wmqlhWU3zFCjizcmd+NaTjis0O4XJbMhusRvWxQlswE1ZcSVLcuEPfLgaLWWm
LENLOdHTLiufpibdN2/cuJDQPj3O6jrSZRmU2/5xZoz7sSfVzTFLqOCiwNvjnQGlgraHO3PwFMyv
kz8SL5DGSKrGkQFjCk9pDP7pxX/nNRGnqkHN5f30LTuNwMbcK/kbsjpVrM3uewckIGNUcqc8QxRJ
phVrZs26VYTh2xAXqz9/wNwrN1YL7CWA7a9lsA==</ds:X509Certificate>
                </ds:X509Data>
            </ds:KeyInfo>
        </ds:Signature>
        <saml2:Subject xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">
            <saml2:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">pranavi.20bcr7011@vitap.ac.in</saml2:NameID>
            <saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
                <saml2:SubjectConfirmationData NotOnOrAfter="2024-03-06T09:53:59.266Z"
                                               Recipient="http://localhost:5000/user/saml/login"
                                               />
            </saml2:SubjectConfirmation>
        </saml2:Subject>
        <saml2:Conditions xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"
                          NotBefore="2024-03-06T09:43:59.266Z"
                          NotOnOrAfter="2024-03-06T09:53:59.266Z"
                          >
            <saml2:AudienceRestriction>
                <saml2:Audience>http://localhost:5000/user/saml/login</saml2:Audience>
            </saml2:AudienceRestriction>
        </saml2:Conditions>
        <saml2:AuthnStatement xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"
                              AuthnInstant="2024-03-06T09:48:59.266Z"
                              SessionIndex="id1709718539119.710670496"
                              >
            <saml2:AuthnContext>
                <saml2:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml2:AuthnContextClassRef>
            </saml2:AuthnContext>
        </saml2:AuthnStatement>
        <saml2:AttributeStatement xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">
            <saml2:Attribute Name="Email"
                             NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified"
                             >
                <saml2:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema"
                                      xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                                      xsi:type="xs:string"
                                      >pranavi.20bcr7011@vitap.ac.in</saml2:AttributeValue>
            </saml2:Attribute>
            <saml2:Attribute Name="Password"
                             NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified"
                             >
                <saml2:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema"
                                      xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                                      xsi:type="xs:string"
                                      />
            </saml2:Attribute>
        </saml2:AttributeStatement>
    </saml2:Assertion>
</saml2p:Response>
"""

def element_to_dict(element):
    """
    Convert an ElementTree element to a dictionary recursively.
    """
    # Initialize the dictionary with tag name and attributes
    result = {
        "tag": element.tag,
        "attrib": element.attrib,
    }
    # Process the text content if it exists
    if element.text:
        result["text"] = element.text.strip()
    # Process any child elements recursively
    if len(element) > 0:
        result["children"] = [element_to_dict(child) for child in element]
    return result

# Parse the SAML response XML string into an ElementTree object
root = ET.fromstring(saml_response)

# Convert the ElementTree object to a dictionary
response_dict = element_to_dict(root)

# Print the resulting dictionary
print(response_dict)


# Find the Assertion element
assertion_element = root.find(".//saml2:Assertion", namespaces={'saml2': 'urn:oasis:names:tc:SAML:2.0:assertion'})

# Check if Assertion element exists
if assertion_element is not None:
    # Initialize assertion attributes dictionary
    assertion_attributes = {}
    
    # Find Attribute elements within Assertion
    attribute_elements = assertion_element.findall(".//saml2:Attribute", namespaces={'saml2': 'urn:oasis:names:tc:SAML:2.0:assertion'})
    
    # Loop through Attribute elements
    for attribute_element in attribute_elements:
        # Extract attribute name
        attribute_name = attribute_element.attrib.get('Name')
        
        # Extract attribute value(s) if they exist
        attribute_values = [value.text.strip() for value in attribute_element.findall(".//saml2:AttributeValue", namespaces={'saml2': 'urn:oasis:names:tc:SAML:2.0:assertion'}) if value.text is not None]
        
        # Add attribute to assertion attributes dictionary
        assertion_attributes[attribute_name] = attribute_values
    
    # Print assertion attributes dictionary
    print("Assertion Attributes:")
    print(assertion_attributes)
else:
    print("\nAssertion element not found in the XML.")

