<?php

namespace GoFinTech\ServiceAuth;

use LogicException;

/**
 * Handles password decoding
 * @package GoFinTech\ServiceAuth
 * @copyright Go Financial Technologies. See LICENSE file for details.
 */
class CredentialHandler
{
    /** @var string */
    private $authKey;
    /** @var string */
    private $iv;

    /**
     * Initializes auth state from configuration file.
     * The file contains a shared secret to use for password decryption.
     * @param string|null $authFile Config file. If not specified, AUTHORIZATION_CREDENTIALS env is used.
     */
    public function __construct(string $authFile = null)
    {
        if (empty($authFile)) {
            $authFile = getenv('AUTHORIZATION_CREDENTIALS');
        }
        if (empty($authFile)) {
            // Uninitialized state, useful for development
            return;
        }

        $config = json_decode(file_get_contents($authFile), true);
        $this->authKey = $config['authKey'];
        // There is enough secret in the key itself and there is no easy way to generate IV from
        // other source than the config file itself.
        $this->iv = base64_decode('n8EaEtujjeQ0Lj3AFR4qQg==');
    }

    /**
     * Decodes password if necessary.
     * Encrypted passwords have a schema prefix.
     * If there is no such prefix or it is unknown, no decryption happens.
     * NOTE You shouldn't pass user-supplied or otherwise unsafe data to this function
     * @param string $password
     * @return string decrypted password
     * @throws LogicException if the instance is not initialized but password decryption is required
     */
    public function decodePassword(string $password): string
    {
        $p = strpos($password, ':');
        if ($p === false)
            return $password;
        $schema = substr($password, 0, $p);
        if ($schema != 'authKey')
            return $password;

        if (empty($this->authKey))
            throw new LogicException("CredentialHandler: service authorization not fully initialized");

        $cypher = substr($password, $p + 1);
        $password = openssl_decrypt($cypher, 'AES-128-CBC', $this->authKey, 0, $this->iv);

        return $password;
    }
}
