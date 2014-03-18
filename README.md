# Attribute Authority for simpleSAMLphp

Derived from (https://code.google.com/p/aa4ssp)


The apache2 required config for simplesamlphp location:

        SSLOptions +StdEnvVars +ExportCertData
        SSLVerifyClient optional_no_ca
        
Introduction

The configuration of the modul is in config-templates/module-aa.php.

You can change the time window of the request expiration and the class of the AttributeResolver.

There is only one AttributeResolver handle and this is for the YAVOM software. If you want to implement your attribute source, don't hesitate.

You should copy and edit from metadata-templates/attributeauthority-hosted.php to metadata directory. After this the metadata is provided at the

    <simplesamlphp_instance>/module.php/aa/metadata.php?output=xhtml

web URL in the usual formats.