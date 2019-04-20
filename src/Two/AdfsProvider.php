<?php

namespace Laravel\Socialite\Two;

use Illuminate\Support\Arr;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Signer\Keychain;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\ValidationData;

class AdfsProvider extends AbstractProvider implements ProviderInterface
{
    /**
     * The separating character for the requested scopes.
     *
     * @var string
     */
    protected $scopeSeparator = ' ';


    /**
     * Adfs server url
     * @var string
     */
    public $adfs_url = '';


    /**
     * Audience of jwt token to validate
     *
     */

    public $jwt_aud = '';

    /**
     * Path to public key file to verify jwt
     *
     */
    public $jwt_pub_key_file = '';

    /**
     *  Issuer name in jwt
     */
    public $jw_issuer = '';

    /**
     * Add "login with" button or redirect automatically
     *
     */
    public $auto_redirect = true;

    /**
     * The scopes being requested.
     *
     * @var array
     */
    protected $scopes = [
        'openid',
        'profile',
        'email',
    ];

    /**
     * {@inheritdoc}
     */
    protected function getAuthUrl($state)
    {
        return $this->buildAuthUrlFromBase($this->adfs_url.'/adfs/oauth2/authorize', $state);
    }

    /**
     * {@inheritdoc}
     */
    protected function getTokenUrl()
    {
        return $this->adfs_url.'/adfs/oauth2/token';
    }

    /**
     * Get the POST fields for the token request.
     *
     * @param  string  $code
     * @return array
     */
    protected function getTokenFields($code)
    {
        return array_add(
            parent::getTokenFields($code), 'grant_type', 'authorization_code'
        );
    }

    /**
     * {@inheritdoc}
     */
    protected function getUserByToken($token)
    {
        // Parse token string to token object
        $token = (new Parser())->parse((string) $token);

        // Validate token
        $data = new ValidationData();
        $data->setIssuer($this->jw_issuer);
        $data->setAudience($this->jwt_aud);
        if (!$token->validate($data)) return null;

        // Verify signature
        $keychain = new Keychain();
        $signer = new Sha256();
        if(!$token->verify($signer, $keychain->getPublicKey($this->jwt_pub_key_file))) return null;


        // Map claims to user array
        $user["employeeid"] = $token->getClaim("employeeid");
        $user["clockid"] = $token->getClaim("employeeid");
        $user["displayname"] = $token->getClaim("displayname");
        $user["email"] = $token->getClaim("Email");
        $user["ext_attrs"] = $token->getClaims();

        return  $user;
    }

    /**
     * {@inheritdoc}
     */
    protected function mapUserToObject(array $user)
    {
        if (empty($user)) return;
        $retUser = (new User())->setRaw($user)->map([
            'id' => Arr::get($user, 'clockid'),
            'email' => Arr::get($user, 'email'),
            'name' => Arr::get($user, 'displayname')
        ]);

        return $retUser;
    }

    public function setSSLOptions(array $options){
        //$this->ht
    }
}
