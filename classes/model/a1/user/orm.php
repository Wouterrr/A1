<?php

/* 
 * Abstract A1 Authentication User Model
 * To be extended and completed to user's needs
 * (see a2acldemo/classes/model/user.php for an example implementation)
 */

abstract class Model_A1_User_ORM extends ORM {

	// A1 config file name
	protected $_config = 'a1';

	// user model (from config)
	protected $_user_model;

	// user columns (from config)
	protected $_columns;

	protected function _initialize()
	{
		parent::_initialize();

		$this->_columns        = Kohana::config($this->_config)->columns;
		$this->_user_model     = Kohana::config($this->_config)->user_model;
	}

	public function save(Validation $validation = NULL)
	{
		if(array_key_exists( $this->_columns['password'] ,$this->_changed))
		{
			$this->_object[ $this->_columns['password'] ] = A1::instance($this->_config)->hash($this->_object[ $this->_columns['password'] ]);
		}

		return parent::save($validation);
	}
}
