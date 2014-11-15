# Attribute Authority for simpleSAMLphp

* Author: Gyula Szabó <gyufi@niif.hu>, NIIF Institute, Hungary

This module provides back-end SAML Attribute Authority functionality.

## Install module
You can install the module with composer:

    composer require niif/simplesamlphp-module-aa:1.*

## Apache configuration
The following Apache configuration is required for the SimpleSAMLphp request path:

        SSLOptions +StdEnvVars +ExportCertData
        SSLVerifyClient optional_no_ca
       
## Module configuration 
The module configuration example is in `config-templates/module-aa.php`. You can configure the response validity time, the defined authsource and the signing properties.

### Authentication Source
Because the principal can not be authenticated, there must be an authsource that populates the query subject in an attribute, that can be further processed by Authentication Processing Filters. It is implemented by a dummy authsource called `aa:Bypass`. 

You can configure the field that will hold the query subject in `config/authsources.php` as the following:

       'default-aa' => array(
                'aa:Bypass',
                'uid' => 'subject_nameid',
        ),


### Authproc Filters
In the `config/config.php` you can define an array named "authproc.aa", just like authproc.sp or authproc.idp. The NameID of the request will be in the attribute as defined above. For example, you can add attributes to the response with `attributecollector:AttributeCollector` or `ldap:AttributeAddFromLDAP`.

### Metadata
You should copy `metadata-templates/attributeauthority-hosted.php` to the `metadata` directory and customise it. The metadata is published at

    <simplesamlphp_instance>/module.php/aa/metadata.php?output=xhtml

URL in the usual formats. The metadata contains the proper signing certificate.

This code has derived from the old [aa4ssp code](https://code.google.com/p/aa4ssp).
