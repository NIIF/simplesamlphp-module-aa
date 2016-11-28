<?php
$config = array(
    /**
     * Validity of the response (in seconds)
     *
     */
     'validFor' => 5*60,

    /**
     * AuthSource of the attribute source
     *
     */
     'authsource' => 'default-aa',
     
     /**
      * Sign the response, deafult is true.
      */
      //'signResponse' => TRUE,

    /**
     * Sign the whole assertion, default is false.
     */
     //'signAssertion' => FALSE,

     /**
     * Header variable that contain the ssl client certificate, default is SSL_CLIENT_CERT.
     * Useful when the AA is behind load balancer.
     */
     //'sslClientCertContainer' => 'SSL_CLIENT_CERT',
         

);
