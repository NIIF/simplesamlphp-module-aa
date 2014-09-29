# Attribute Authority for simpleSAMLphp

* Author: Gyula Szabó <gyufi@niif.hu>, NIIF Institute, Hungary

This module provide a back-end SAML Attribute Authority implementation.



## Apache configuration
The following Apache configuration is required for the SimpleSAMLphp request path:

        SSLOptions +StdEnvVars +ExportCertData
        SSLVerifyClient optional_no_ca
       
## Module configuration 
The module configuration example is in <code>config-templates/module-aa.php</code>. You have to configure the response validity time, the defined authsource and the signing.

## etc/authsource.php
The authsource configuration is depend on the attribute resolver class. The authsource is has to be passive, without user interaction, and it receive the pricipal in the $state['aa:nameId'] variable.

## Authproc Filters
In the etc/config.php you can define an array named "authproc.aa" - like authproc.sp or authproc.idp - and you shoud configure attribute filter classes, to manipulate the given attributes.

## Metadata
You should copy and edit from metadata-templates/attributeauthority-hosted.php to metadata directory. After this the metadata is provided at the

    <simplesamlphp_instance>/module.php/aa/metadata.php?output=xhtml

web URL in the usual formats.

The metadata contains the signing certificate informations.

This code derived from the old [aa4ssp code](https://code.google.com/p/aa4ssp).