<?php
namespace SimpleWpMcpAdapterOAuth\OAuth\Entities;

use League\OAuth2\Server\Entities\UserEntityInterface;
use League\OAuth2\Server\Entities\Traits\EntityTrait;

class UserEntity implements UserEntityInterface {

	use EntityTrait;

	public function __construct( $identifier ) {
		$this->setIdentifier( $identifier );
	}
}
