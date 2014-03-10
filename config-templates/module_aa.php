<?php
$config = array(
		
    /**
		 * attribute request expiration in seconds
     */
		'timewindow' => 5*60,

		/**
		 * AttributeResolver class
     *
     */
		//'resolver' => 'Yavom',

		/*
		 'testvalue' => array(
		 		'urn:oid:1.3.6.1.4.1.5923.1.1.1.7'=>'test1_Entitlement_from_YAVOM_UsingOnlyTest',
		 ),
     */
  
      'resolver' => 'PDO',


      'dsn' => 'mysql:host=localhost;dbname=aadatabase',
      'username' => 'user',
      'password' => 'pass',
      
      /*
	HEXAA REST API URL, only needed if resolver='Hexaa'.
	Note: Do not write / at the end!
      */
      //'hexaa_api_url' => 'http://localhost/hexaa/api',

      'fid_attribute_name'=>'eduPersonPrincipalName',

       /**
        * Must have {{ fid }} tag for given persistent ID
        * like eduPersonPrincipalName
        * select ONLY ONE column. Othervise the first column of result will be processed.
       */
      'select' => "SELECT urn FROM aa WHERE persistentID = {{ fid }}",

      'spid_urnregexp_map' => array(
              'https://noc2b.vh.hbone.hu/shibboleth' => array('cvsweb'),
      ),

      /**
       *
       * ExampleStatic
       *
       * attributes are array of arrays, attribute name and array of values.
       */
      /*
      'resolver' => 'ExampleStatic',
      'attributes' => array(
        'urn:oid:1.3.6.1.4.1.5923.1.1.1.7' => array(
                'urn:oid:test-from-examplestatic' // eduPersonEntitlement
                ),
        'urn:oid:0.9.2342.19200300.100.1.3' => array(
                'testuser+from-examplestatic@example.com' //mail
                )
      )
      */
);
