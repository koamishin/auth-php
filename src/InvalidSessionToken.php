<?php

declare(strict_types=1);

namespace Koamishin\Auth;

use RuntimeException;

/**
 * A session token failed verification: it is malformed, expired, signed by
 * someone else, or bound to a different application.
 */
class InvalidSessionToken extends RuntimeException {}
