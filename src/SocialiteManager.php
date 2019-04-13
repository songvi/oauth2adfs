<?php

namespace Laravel\Socialite;

use InvalidArgumentException;
use Illuminate\Support\Manager;
use Laravel\Socialite\One\TwitterProvider;
use Laravel\Socialite\One\BitbucketProvider;
use Laravel\Socialite\Two\AdfsProvider;
use League\OAuth1\Client\Server\Twitter as TwitterServer;
use League\OAuth1\Client\Server\Bitbucket as BitbucketServer;
use League\OAuth1\Client\Server\AdfsServer as AdfsServer;

class SocialiteManager extends Manager implements Contracts\Factory
{
    /**
     * Get a driver instance.
     *
     * @param  string  $driver
     * @return mixed
     */
    public function with($driver)
    {
        return $this->driver($driver);
    }

    /**
     * Build an OAuth 2 provider instance.
     *
     * @param  string  $provider
     * @param  array  $config
     * @return \Laravel\Socialite\Two\AbstractProvider
     */
    public function buildProvider($provider, $config)
    {
        $adfsProvider = new $provider(
            $this->app['request'], $config['client_id'],
            $config['client_secret'], $config['redirect']
        );
        $adfsProvider->jwt_aud = $config['jwt_aud'];
        $adfsProvider->adfs_url = $config['adfs_url'];
        $adfsProvider->jwt_pub_key_file = $config['jwt_pub_key_file'];
        $adfsProvider->jwt_issuer = $config['jwt_issuer'];

        return $adfsProvider;
    }

    /**
     * Create an instance of the specified driver.
     *
     * @return \Laravel\Socialite\Two\AbstractProvider
     */
    protected function createAdfsDriver()
    {
        $config = $this->app['config']['services.adfs'];

        return $this->buildProvider(
            'Laravel\Socialite\Two\AdfsProvider', $config
        );
    }

    /**
     * Format the server configuration.
     *
     * @param  array  $config
     * @return array
     */
    public function formatConfig(array $config)
    {
        return array_merge([
            'identifier' => $config['client_id'],
            'secret' => $config['client_secret'],
            'callback_uri' => $config['redirect'],
            'jwt_aud' => $config['jwt_aud'],
            'adfs_url' => $config['adfs_url'],
            'jwt_pub_key_file' => $config['jwt_pub_key_file'],
            'jwt_issuer' => $config['jwt_issuer']
        ], $config);
    }

    /**
     * Get the default driver name.
     *
     * @throws \InvalidArgumentException
     *
     * @return string
     */
    public function getDefaultDriver()
    {
        throw new InvalidArgumentException('No Socialite driver was specified.');
    }
}
