<?php defined('SYSPATH') or die('No direct access allowed.');

/* 
 * Abstract A1 Authentication User Model
 * To be extended and completed to user's needs
 *
 * Remember to validate data before saving to database. Some validation rules are already taken care of by the _fields declaration.
 * Min_length and max_length are set for both username and password, both these fields are already required, and the username
 * will be checked on uniqueness. However, you might want to add additional rules to validate if username is alphanumeric for example.
 */

abstract class Model_A1_User_Mango extends Mango {

	protected $_fields = array(
		'username'   => array( 'type' => 'string', 'required' => TRUE, 'min_length' => 4, 'max_length' => 50, 'unique' => TRUE),
		'password'   => array( 'type' => 'string', 'required' => TRUE, 'min_length' => 5, 'max_length' => 50),

		//'logins'          => array('type' => 'counter')
		//'last_login'      => array('type' => 'int'),
		//'last_attempt'    => array('type' => 'int'),
		//'failed_attempts' => array('type' => 'counter')
	);

	// Specify config name so password gets hashed correctly (with the right salt pattern) when set in user
	protected $_name = 'a1';

	public function create($safe = TRUE)
	{
		$this->password = $this->hash($this->password);
		return parent::create($safe);
	}

	public function update($criteria = array(), $safe = TRUE)
	{
		if (isset($this->_changed['password']))
		{
			$this->password = $this->hash($this->password);
		}

		return parent::update($criteria, $safe);
	}

	public function hash($password)
	{
		return A1::instance($this->_name)->hash($password);
	}
}
