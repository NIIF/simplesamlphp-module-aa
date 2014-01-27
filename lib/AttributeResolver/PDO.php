<?php
class sspmod_aa_AttributeResolver_PDO extends sspmod_aa_AttributeResolver
{
    public function __construct($config){
        parent::__construct($config);
    }

	public function getAttributes($spid,$eppn,$attributes = array())
	{
        $config = $this->config;
		$epe = 'urn:oid:1.3.6.1.4.1.5923.1.1.1.7';
		$retarray = array();
                /* TODO check config, is there {{ fid }} in 'select' */
                
                try {
                    SimpleSAML_Logger::notice('[aa] PDO attribute resolving for '.$eppn.' started.');
                    $dbh = new PDO($config->getValue('dsn'),$config->getValue('username'),$config->getValue('password'));
                    $dbh->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
                    $sql = preg_replace('/\{\{ fid \}\}/','"'.$eppn.'"',$config->getValue('select'));
                    SimpleSAML_Logger::debug('[aa] PDO: sql: '.$sql);
                    $sth = $dbh->prepare($sql);
                    $sth->execute();
                    $result = $sth->fetchAll(PDO::FETCH_COLUMN, 0);
                    SimpleSAML_Logger::debug('[aa] PDO: result: '.var_export($result,TRUE));
                    $map = $config->getArray('spid_urnregexp_map');
                    foreach ($result as $row)
                    {
                        if (array_key_exists($spid,$map)){
                            foreach($map[$spid] as $pattern){
                                if (preg_match('/^.*'.$pattern.'.*$/',$row)){
                                    $retarray[$epe][] = $row;
                                    break;
                                }
                            }
                        }
                    }

                    /*** close the database connection ***/
                    $dbh = null;
                }
                catch(PDOException $e)
                {
                   throw new SimpleSAML_Error_Exception('AttributeResovler PDO error: '.$e->getMessage());
                }

		$attrnum = ( isset( $retarray[$epe] ) ) ? count( $retarray[$epe] ) : 0;

                SimpleSAML_Logger::debug('[aa] PDO: emitted attributes: '.var_export($retarray,TRUE));
                SimpleSAML_Logger::notice('[aa] PDO attribute resolving for '.$eppn.' ended. Emitted '.$attrnum.' attribute values to sp: '.$spid );
		return $retarray;
	}
}
