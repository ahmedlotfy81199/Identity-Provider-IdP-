<?php

namespace App\Http\Controllers;

use App\Models\User;
use OneLogin\Saml2\Auth;
use OneLogin\Saml2\Utils;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth as userAuth;
use OneLogin\Saml2\Auth as OneLoginAuth;

class Saml2Controller extends Controller
{
    protected $saml2Auth;

    public function __construct()
    {
        $settings = config('saml2_settings');
        $this->saml2Auth = new Auth($settings);
    }

    public function metadata()
    {
        $settings = $this->saml2Auth->getSettings();
        $metadata = $settings->getSPMetadata();
        $errors = $settings->validateMetadata($metadata);
        if (!empty($errors)) {
            throw new \OneLogin\Saml2\Error(
                'Invalid SP metadata: ' . implode(', ', $errors),
                \OneLogin\Saml2\Error::METADATA_SP_INVALID
            );
        }
        return response($metadata, 200, ['Content-Type' => 'text/xml']);
    }

    public function acs(Request $request)
    {
        $credentials = $request->only('email', 'password');
        if (userAuth::attempt($credentials)) {
            // Retrieve the saved SAMLRequest and RelayState
            $samlRequest = session('SAMLRequest');
            $relayState = session('RelayState');

            // Get the authenticated user
            $user = userAuth::user();

            // Create SAML response
            $samlResponse = $this->createSAMLResponse($user->email);
            // Encode the SAML response
            $samlResponseEncoded = base64_encode($samlResponse);

            // Prepare HTML form for POST request to SP
            $html = '
            <!DOCTYPE html>
            <html>
            <head>
                <title>Redirecting...</title>
            </head>
            <body>
                <form id="saml-form" method="POST" action="' . htmlspecialchars($relayState) . '">
                    <input type="hidden" name="SAMLResponse" value="' . htmlspecialchars($samlResponseEncoded, ENT_QUOTES) . '" />
                    <input type="hidden" name="RelayState" value="' . htmlspecialchars($relayState, ENT_QUOTES) . '" />
                </form>
                <script>
                    document.getElementById("saml-form").submit();
                </script>
            </body>
            </html>';

            // Return HTML response
            return response($html);
        } else {
            return redirect()->back()->withErrors(['Invalid credentials']);
        }
    }

    public function sls()
    {
        $this->saml2Auth->processSLO();
        return redirect('/');
    }

    public function login(Request $request)
    {
        session(['SAMLRequest' => $request->input('SAMLRequest')]);
        session(['RelayState' => $request->input('RelayState')]);

        return view('auth/login');
    }


    private function createSAMLResponse($email)
    {
        $samlSettings = $this->saml2Auth->getSettings();
        $requestId = $this->saml2Auth->getLastRequestId();
        $issuer = $samlSettings->getIdPData()['entityId'];
        $acsUrl = $samlSettings->getSPData()['assertionConsumerService']['url'];

        // Create the assertion
        $assertion = new \DOMDocument('1.0', 'utf-8');
        $assertion->loadXML('<Assertion xmlns="urn:oasis:names:tc:SAML:2.0:assertion"></Assertion>');

        // Create the Subject
        $subject = $assertion->createElement('Subject');
        $nameID = $assertion->createElement('NameID', htmlspecialchars($email));
        $nameID->setAttribute('Format', 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress');
        $subject->appendChild($nameID);

        $subjectConfirmation = $assertion->createElement('SubjectConfirmation');
        $subjectConfirmation->setAttribute('Method', 'urn:oasis:names:tc:SAML:2.0:cm:bearer');

        $subjectConfirmationData = $assertion->createElement('SubjectConfirmationData');
        $subjectConfirmationData->setAttribute('Recipient', $acsUrl);
        $subjectConfirmationData->setAttribute('InResponseTo', $requestId);
        $subjectConfirmationData->setAttribute('NotOnOrAfter', gmdate('Y-m-d\TH:i:s\Z', time() + 3600));

        $subjectConfirmation->appendChild($subjectConfirmationData);
        $subject->appendChild($subjectConfirmation);

        $assertion->documentElement->appendChild($subject);

        // Create the Conditions
        $conditions = $assertion->createElement('Conditions');
        $conditions->setAttribute('NotBefore', gmdate('Y-m-d\TH:i:s\Z', time() - 300));
        $conditions->setAttribute('NotOnOrAfter', gmdate('Y-m-d\TH:i:s\Z', time() + 3600));

        $audienceRestriction = $assertion->createElement('AudienceRestriction');
        $audience = $assertion->createElement('Audience', $samlSettings->getSPData()['entityId']);
        $audienceRestriction->appendChild($audience);

        $conditions->appendChild($audienceRestriction);
        $assertion->documentElement->appendChild($conditions);

        // Create the AuthnStatement
        $authnStatement = $assertion->createElement('AuthnStatement');
        $authnStatement->setAttribute('AuthnInstant', gmdate('Y-m-d\TH:i:s\Z', time()));

        $authnContext = $assertion->createElement('AuthnContext');
        $authnContextClassRef = $assertion->createElement('AuthnContextClassRef', 'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport');
        $authnContext->appendChild($authnContextClassRef);

        $authnStatement->appendChild($authnContext);
        $assertion->documentElement->appendChild($authnStatement);

        // Create the AttributeStatement
        $attributeStatement = $assertion->createElement('AttributeStatement');

        $emailAttribute = $assertion->createElement('Attribute');
        $emailAttribute->setAttribute('Name', 'email');

        $emailAttributeValue = $assertion->createElement('AttributeValue', htmlspecialchars($email));
        $emailAttributeValue->setAttribute('xmlns:xs', 'http://www.w3.org/2001/XMLSchema');
        $emailAttributeValue->setAttribute('xmlns:xsi', 'http://www.w3.org/2001/XMLSchema-instance');
        $emailAttributeValue->setAttribute('xsi:type', 'xs:string');

        $emailAttribute->appendChild($emailAttributeValue);
        $attributeStatement->appendChild($emailAttribute);

        $assertion->documentElement->appendChild($attributeStatement);

        // Create the Response
        $response = new \DOMDocument('1.0', 'utf-8');
        $response->loadXML('<Response xmlns="urn:oasis:names:tc:SAML:2.0:protocol"></Response>');

        $response->documentElement->setAttribute('ID', '_' . \OneLogin\Saml2\Utils::generateUniqueID());
        $response->documentElement->setAttribute('Version', '2.0');
        $response->documentElement->setAttribute('IssueInstant', gmdate('Y-m-d\TH:i:s\Z'));
        $response->documentElement->setAttribute('InResponseTo', $requestId);

        $issuerElement = $response->createElement('Issuer', htmlspecialchars($issuer));
        $response->documentElement->appendChild($issuerElement);

        $status = $response->createElement('Status');
        $statusCode = $response->createElement('StatusCode');
        $statusCode->setAttribute('Value', 'urn:oasis:names:tc:SAML:2.0:status:Success');
        $status->appendChild($statusCode);
        $response->documentElement->appendChild($status);

        $response->documentElement->appendChild($response->importNode($assertion->documentElement, true));

        return $response->saveXML();
    }
}
