/**
 * SAML 2.0 AA configuration for simpleSAMLphp.
 *
 */

$metadata['https://aai.sztaki.hu/vo'] = array(
        /*
         * The hostname of the server (VHOST) that will use this SAML entity.
         *
         * Can be '__DEFAULT__', to use this entry by default.
         */
        'host' => '__DEFAULT__',

        /* X.509 key and certificate. Relative to the cert directory. */
        'privatekey' => 'server.pem',
        'certificate' => 'server.crt',

        'OrganizationName' => 'MTA SZTAKI',
        'OrganizationDisplayName' => 'MTA SZTAKI',
        'OrganizationURL' => 'http://www.sztaki.hu',

);
