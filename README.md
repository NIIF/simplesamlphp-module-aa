# Attribute Authority for simpleSAMLphp

Derived from (https://code.google.com/p/aa4ssp)


The following Apache configuration is required for the SimpleSAMLphp request path:

        SSLOptions +StdEnvVars +ExportCertData
        SSLVerifyClient optional_no_ca
        
The configuration of the module is in <code>config-templates/module-aa.php</code>.

You can change the clock skew allowed for requests and the attribute source.

You should copy and edit from metadata-templates/attributeauthority-hosted.php to metadata directory. After this the metadata is provided at the

    <simplesamlphp_instance>/module.php/aa/metadata.php?output=xhtml

web URL in the usual formats.
