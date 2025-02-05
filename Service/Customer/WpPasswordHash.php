<?php

namespace SapientPro\WpMigration\Service\Customer;

class WpPasswordHash {
    /**
     * @var string
     */
    private $itoa64;

    /**
     * @var int|mixed
     */
    private $iteration_count_log2;

    /**
     * @var mixed|true
     */
    private $portable_hashes;

    /**
     * @var string
     */
    private string $random_state;

    /**
     * Hash Password Constructor
     *
     * @param int $iteration_count_log2
     * @param bool $portable_hashes
     */
    function __construct(int $iteration_count_log2 = 8, bool $portable_hashes = true)
    {
        $this->itoa64 = './0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';

        if ($iteration_count_log2 < 4 || $iteration_count_log2 > 31)
            $iteration_count_log2 = 8;
        $this->iteration_count_log2 = $iteration_count_log2;

        $this->portable_hashes = $portable_hashes;

        $this->random_state = microtime();
        if (function_exists('getmypid'))
            $this->random_state .= getmypid();
    }

    /**
     * Password Hash
     *
     * @param int $iteration_count_log2
     * @param $portable_hashes
     * @return void
     */
    public function passwordHash(int $iteration_count_log2 = 8, $portable_hashes = true)
    {
        self::__construct($iteration_count_log2, $portable_hashes);
    }

    /**
     * Get random bytes
     *
     * @param $count
     * @return false|string
     */
    public function getRandomBytes($count)
    {
        $output = '';
        if (@is_readable('/dev/urandom') &&
            ($fh = @fopen('/dev/urandom', 'rb'))) {
            $output = fread($fh, $count);
            fclose($fh);
        }

        if (strlen($output) < $count) {
            $output = '';
            for ($i = 0; $i < $count; $i += 16) {
                $this->random_state =
                    md5(microtime() . $this->random_state);
                $output .= md5($this->random_state, TRUE);
            }
            $output = substr($output, 0, $count);
        }

        return $output;
    }

    /**
     * Encode 64
     *
     * @param $input
     * @param $count
     * @return string
     */
    public function encode64($input, $count): string
    {
        $output = '';
        $i = 0;
        do {
            $value = ord($input[$i++]);
            $output .= $this->itoa64[$value & 0x3f];
            if ($i < $count)
                $value |= ord($input[$i]) << 8;
            $output .= $this->itoa64[($value >> 6) & 0x3f];
            if ($i++ >= $count)
                break;
            if ($i < $count)
                $value |= ord($input[$i]) << 16;
            $output .= $this->itoa64[($value >> 12) & 0x3f];
            if ($i++ >= $count)
                break;
            $output .= $this->itoa64[($value >> 18) & 0x3f];
        } while ($i < $count);

        return $output;
    }

    /**
     * Generate salt private
     *
     * @param $input
     * @return string
     */
    public function genSaltPrivate($input): string
    {
        $output = '$P$';
        $output .= $this->itoa64[min($this->iteration_count_log2 +
            ((PHP_VERSION >= '5') ? 5 : 3), 30)];
        $output .= $this->encode64($input, 6);

        return $output;
    }

    /**
     * Crypt private
     *
     * @param $password
     * @param $setting
     * @return string
     */
    public function cryptPrivate($password, $setting): string
    {
        $output = '*0';
        if (substr($setting, 0, 2) === $output)
            $output = '*1';

        $id = substr($setting, 0, 3);
        # We use "$P$", phpBB3 uses "$H$" for the same thing
        if ($id !== '$P$' && $id !== '$H$')
            return $output;

        $count_log2 = strpos($this->itoa64, $setting[3]);
        if ($count_log2 < 7 || $count_log2 > 30)
            return $output;

        $count = 1 << $count_log2;

        $salt = substr($setting, 4, 8);
        if (strlen($salt) !== 8)
            return $output;

        # We were kind of forced to use MD5 here since it's the only
        # cryptographic primitive that was available in all versions
        # of PHP in use.  To implement our own low-level crypto in PHP
        # would have resulted in much worse performance and
        # consequently in lower iteration counts and hashes that are
        # quicker to crack (by non-PHP code).
        $hash = md5($salt . $password, TRUE);
        do {
            $hash = md5($hash . $password, TRUE);
        } while (--$count);

        $output = substr($setting, 0, 12);
        $output .= $this->encode64($hash, 16);

        return $output;
    }

    /**
     * Gen salt blowfish
     *
     * @param $input
     * @return string
     */
    public function genSaltBlowFish($input): string
    {
        # This one needs to use a different order of characters and a
        # different encoding scheme from the one in encode64() above.
        # We care because the last character in our encoded string will
        # only represent 2 bits.  While two known implementations of
        # bcrypt will happily accept and correct a salt string which
        # has the 4 unused bits set to non-zero, we do not want to take
        # chances and we also do not want to waste an additional byte
        # of entropy.
        $itoa64 = './ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';

        $output = '$2a$';
        $output .= chr((int)(ord('0') + $this->iteration_count_log2 / 10));
        $output .= chr((ord('0') + $this->iteration_count_log2 % 10));
        $output .= '$';

        $i = 0;
        do {
            $c1 = ord($input[$i++]);
            $output .= $itoa64[$c1 >> 2];
            $c1 = ($c1 & 0x03) << 4;
            if ($i >= 16) {
                $output .= $itoa64[$c1];
                break;
            }

            $c2 = ord($input[$i++]);
            $c1 |= $c2 >> 4;
            $output .= $itoa64[$c1];
            $c1 = ($c2 & 0x0f) << 2;

            $c2 = ord($input[$i++]);
            $c1 |= $c2 >> 6;
            $output .= $itoa64[$c1];
            $output .= $itoa64[$c2 & 0x3f];
        } while (1);

        return $output;
    }

    /**
     * Hash Password
     *
     * @param $password
     * @return string|null
     */
    public function hashPassword($password): ?string
    {
        if ( strlen( $password ) > 4096 ) {
            return '*';
        }

        $random = '';

        if (CRYPT_BLOWFISH === 1 && !$this->portable_hashes) {
            $random = $this->getRandomBytes(16);
            $hash =
                crypt($password, $this->genSaltBlowFish($random));
            if (strlen($hash) === 60)
                return $hash;
        }

        if (strlen($random) < 6)
            $random = $this->getRandomBytes(6);
        $hash =
            $this->cryptPrivate($password,
                $this->genSaltPrivate($random));
        if (strlen($hash) === 34)
            return $hash;

        # Returning '*' on error is safe here, but would _not_ be safe
        # in a crypt(3)-like function used _both_ for generating new
        # hashes and for validating passwords against existing hashes.
        return '*';
    }

    /**
     * Check Password
     *
     * @param $password
     * @param $stored_hash
     * @return bool
     */
    public function checkPassword($password, $stored_hash): bool
    {
        if ( strlen( $password ) > 4096 ) {
            return false;
        }

        $hash = $this->cryptPrivate($password, $stored_hash);
        if ($hash[0] === '*')
            $hash = crypt($password, $stored_hash);

        # This is not constant-time.  In order to keep the code simple,
        # for timing safety we currently rely on the salts being
        # unpredictable, which they are at least in the non-fallback
        # cases (that is, when we use /dev/urandom and bcrypt).
        return $hash === $stored_hash;
    }
}
