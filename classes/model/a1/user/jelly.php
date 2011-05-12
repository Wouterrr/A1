<?php defined('SYSPATH') or die('No direct access allowed.');

/**
 * Example:
 *   APPATH/classes/model/user.php:
 *   class Model_User extends Model_A1_User_Jelly {
 *
 *       public static function initialize(Jelly_Meta $meta)
 *       {
 *           $meta->table('user')
 *               ->fields(array(
 *                   'logins' => new Field_Integer,
 *                   //'token' => new Field_String(),
 *               ));
 *
 *           parent::initialize($meta);
 *       }
 *   }
 *
 *   ------------------------------
 *
 *   APPATH/classes/controller/user.php:
 *   class Controller_Frontend_User extends Controller_Frontend_Template {
 *
 *   public function action_signup()
 *   {
 *       // ...
 *
 *       try
 *       {
 *           $user = Jelly::factory('user', array(
 *               'username' => 'user',
 *               'password' => 'bI$hkEk*2bj',
 *               'password' => 'bI$hkEk*2bj',
 *           ))->save();
 *       }
 *       catch(Validate_Exception $e)
 *       {
 *          // catch validate errors
 *       }
 * 
 *       // ...
 *   }
 *   
 */
abstract class Model_A1_User_Jelly extends Jelly_Model {

	/**
	 * @param Jelly_Meta $meta
	 */
	public static function initialize(Jelly_Meta $meta)
	{
		$meta->fields(array(
			'id' => new Field_Primary,
			'username' => Jelly::field('string', array(
				'unique' => TRUE,
					'rules' => array(
						array('not_empty'),
						array('min_length', array(':value', 4)),
						array('max_length', array(':value', 4)),
					)
				)),
			'password' => Jelly::field('password', array(
				'hash_with' => array('Model_A1_User_Jelly', 'hash_password'),
				'rules' => array(
					array('not_empty'),
					array('min_length', array(':value', 6)),
					array('max_length', array(':value', 50)),
				)
			)),
			'password_confirm' => Jelly::field('password', array(
				'in_db' => FALSE,
				'rules' => array(
					array('not_empty'),
					array('min_length', array(':value, 6')),
					array('max_length', array(':value, 50')),
					array('matches', array(':validation', 'password', ':field'))
				)
			)),
		));
	}

	/**
	 * Hash callback using the A1 library
	 *
	 * @param string password to hash
	 * @return string
	 */
	public static function hash_password($password)
	{
		return A1::instance()->hash($password);
	}
}