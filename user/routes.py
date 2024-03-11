from flask import Flask, request, redirect, session
from app import app
import xml.etree.ElementTree as ET
from user.models import User
from util import request as myrequest
import base64
import requests

@app.route('/user/signup', methods=['POST'])
def signup():
    return User().signup()

@app.route('/user/signout')
def signout():
    return User().signout()

@app.route('/user/login', methods=['POST'])
def login():
    return redirect('/user/saml/login')

@app.route('/user/saml/login', methods=['GET', 'POST'])
def saml_login():
    if request.method == 'GET':
        # Generate the SAML authentication request
        entity_id = "http://localhost:5000/user/saml/login"
        acs_url = "http://localhost:5000/user/saml/login"
        authn_request_xml = myrequest.generate_authn_request(entity_id, acs_url)
        print(authn_request_xml)
        
        # Base64 encode the XML
        if authn_request_xml is not None:
            encoded_authn_request = base64.b64encode(authn_request_xml).decode()
            print("SAML Request:")
            print(encoded_authn_request)  # Print the encoded XML
        else:
            print("Error: Authentication request XML is None")

        # Okta SSO endpoint URL
        okta_sso_url = "https://dev-18615030.okta.com/app/dev-18615030_samldemo_3/exkf8znpymURITvYu5d7/sso/saml"

        # Construct the payload for the POST request
        payload = {'SAMLRequest': encoded_authn_request}

        # Send the POST request to Okta
        response = requests.post(okta_sso_url, data=payload)

        # Check the response
        if response.status_code == 200:
            print("SAML authentication request sent successfully.")
        else:
            print(f"Failed to send SAML authentication request. Status code: {response.status_code}")

        return redirect(okta_sso_url)
    
    elif request.method == 'POST':
        saml_response = request.form.get('SAMLResponse')
        # Process the SAML response as needed
        print("Received SAML Response:")
        print(saml_response)

        # # Check if the SAML response is valid
        # if saml_response is not None:
        #     # Parse the SAML response
        #     decoded_response = base64.b64decode(saml_response).decode('utf-8')
        #     root = ET.fromstring(decoded_response)
        
        # #Extract assertion attributes
        # attributes = {}
        # for assertion in root.iter('{urn:oasis:names:tc:SAML:2.0:assertion}Attribute'):
        #     name = assertion.get('Name')
        #     value = assertion.find('{urn:oasis:names:tc:SAML:2.0:assertion}AttributeValue').text
        #     attributes[name] = value
            
        # # Print the parsed SAML response
        # print("\nParsed SAML Response:")
        # print(ET.tostring(root, encoding='utf-8').decode('utf-8'))
            
        # # Print the extracted assertion attributes
        # print("\nExtracted Assertion Attributes:")
        # print(attributes)
            
        # Set up the user session here
        session['logged_in'] = True  
            
        # Redirect to the dashboard
        return redirect('/dashboard')
