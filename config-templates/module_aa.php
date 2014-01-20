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
);
