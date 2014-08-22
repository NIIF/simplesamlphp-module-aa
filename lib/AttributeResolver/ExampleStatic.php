<?php
class sspmod_aa_AttributeResolver_ExampleStatic extends sspmod_aa_AttributeResolver
{

	public function __construct($config)
	{
        parent::__construct($config);
	}

	public function getAttributes($subject, $spid, $attributes = array())
	{
		$config = $this->config;
		$static_attributes = $config->getArray('attributes');
		if (empty($attributes)){
			return $static_attributes;
		}

		$retarray = array();		
		foreach ($attributes as $name => $values) {
			if (array_key_exists($name, $static_attributes))
                                if (! empty($values)) {
                                    foreach($values as $value) {
                                      if ($static_attributes[$name] == $value) {
				    	$retarray[$name] = $static_attributes[$name];
                                      }
                                    }    
                                }
                                else {
				    $retarray[$name] = $static_attributes[$name];
                                }
		}
		return $retarray;
	}
}
