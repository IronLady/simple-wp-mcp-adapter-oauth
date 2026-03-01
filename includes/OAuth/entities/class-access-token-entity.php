<?php
namespace SimpleWpMcpAdapterOAuth\OAuth\Entities;

use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\Traits\AccessTokenTrait;
use League\OAuth2\Server\Entities\Traits\EntityTrait;
use League\OAuth2\Server\Entities\Traits\TokenEntityTrait;

class AccessTokenEntity implements AccessTokenEntityInterface {

	use AccessTokenTrait;
	use EntityTrait;
	use TokenEntityTrait;
}
