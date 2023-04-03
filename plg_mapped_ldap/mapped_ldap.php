<?php
/** @noinspection PhpClassNamingConventionInspection */
/**
 * @package     Mapped LDAP
 * @extension   plg_mapped_ldap
 * @author      James Antrim, <james.antrim@nm.thm.de>
 * @copyright   2021 TH Mittelhessen
 * @license     GNU GPL v.3
 * @link        www.thm.de
 */

defined('_JEXEC') or die;

use Joomla\CMS\Access\Access;
use Joomla\CMS\Authentication\Authentication;
use Joomla\CMS\Authentication\AuthenticationResponse;
use Joomla\CMS\Component\ComponentHelper;
use Joomla\CMS\Language\Text;
use Joomla\CMS\Plugin\CMSPlugin;
use Joomla\CMS\User\User;
use Joomla\CMS\User\UserHelper;
use Joomla\Database\DatabaseDriver;
use Joomla\Registry\Registry;
use LDAP\Connection;

/**
 * Mapped LDAP Authentication Plugin
 */
class PlgAuthenticationMapped_LDAP extends CMSPlugin
{
    // Connection / search
    private const DIRECT = 1, SEARCH = 0;

    public bool $allowReferrals = true;

    protected $autoloadLanguage = true;

    private string $baseFilter = '';

    private Connection $connection;

    /**
     * Triggers error in parent and factory, because they didn't add the db using a container. Seems like if that's what
     * should have been done, then they should have done it...
     *
     * @var DatabaseDriver
     */
    protected $db;

    private string $emailAttribute = '';

    public string $host = '';

    private int $method = 0;

    private string $nameAttribute = '';

    private bool $override = false;

    private int $port = 0;

    private string $query = '';

    public string $userName;

    private string $userPassword = '';

    private string $usersFilter = '';

    /**
     * Destructor.
     */
    public function __destruct()
    {
        $this->unbind();
    }

    /**
     * Binds to the LDAP directory
     *
     * @param   string  $username     The username
     * @param   string  $password     The password
     * @param   bool    $useUsername  ...
     *
     * @return  bool
     */
    public function bind(
        string $username = '',
        string $password = '',
        bool $useUsername = false
    ): bool
    {
        $username = $username ?: $this->userName;
        $password = $password ?: $this->userPassword;

        if (!$this->usersFilter or $useUsername)
        {
            $distinguishedName = $username;
        }
        elseif (strlen($username))
        {
            $distinguishedName = str_replace('[username]', $username, $this->usersFilter);
        }
        else
        {
            $distinguishedName = '';
        }

        return ldap_bind($this->connection, $distinguishedName, $password);
    }

    /**
     * Checks if a subdomain rule is relevant.
     *
     * @param   array  $emails  the emails to check
     * @param   array  $subDomains
     *
     * @return bool
     */
    private function checkSDRelevance(array $emails, array $subDomains): bool
    {
        $domain = (string) $this->params->get('domain');

        foreach ($subDomains as $subDomain)
        {
            foreach ($emails as $email)
            {
                $pieces = explode('@', $email);

                // Invalid or irrelevant
                if (!$emailDomain = array_pop($pieces))
                {
                    continue;
                }

                // Base domain configured => all addresses must have the same base domain
                if ($domain)
                {
                    if (!str_contains($emailDomain, ".$domain"))
                    {
                        continue;
                    }

                    if (str_replace(".$domain", '', $emailDomain) === $subDomain)
                    {
                        return true;
                    }
                }
                // The 'subdomain' is a complete match for the email domain, allowing collected emails from multiple issuers
                elseif ($subDomain === $emailDomain)
                {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Connect to an LDAP server
     *
     * @param   AuthenticationResponse  $response  the joomla response
     *
     * @return  bool
     */
    private function connect(AuthenticationResponse $response): bool
    {
        if (!$this->connection = ldap_connect($this->host, $this->port))
        {
            $response->status        = Authentication::STATUS_FAILURE;
            $response->error_message = Text::_('MAPPED_LDAP_CONNECTION_FAILED');

            return false;
        }

        // Other versions no longer supported => parameter check removed
        if (!ldap_set_option($this->connection, LDAP_OPT_PROTOCOL_VERSION, 3))
        {
            $response->status        = Authentication::STATUS_FAILURE;
            $response->error_message = Text::_('MAPPED_LDAP_OPT_PROTOCOL_VERSION_FAILED');

            return false;
        }

        if (!ldap_set_option($this->connection, LDAP_OPT_REFERRALS, $this->allowReferrals))
        {
            $response->status        = Authentication::STATUS_FAILURE;
            $response->error_message = Text::_('MAPPED_LDAP_OPT_REFERRALS_FAILED');

            return false;
        }

        // Apparently insecure without TLS => parameter check removed
        if (!ldap_start_tls($this->connection))
        {
            $response->status        = Authentication::STATUS_FAILURE;
            $response->error_message = Text::_('MAPPED_LDAP_TLS_NEGOTIATION_FAILED');

            return false;
        }

        return true;
    }

    /**
     * Sets up the array of filters used in searches.
     *
     * @param   string[]  $credentials  the credentials of the user attempting authentication
     *
     * @return array the filter strings
     */
    private function getFilters(array $credentials): array
    {
        $filterUN = ldap_escape($credentials['username'], '', LDAP_ESCAPE_FILTER);
        $filters  = str_replace('[search]', str_replace(';', '\3b', $filterUN), $this->query);
        $filters  = explode(';', $filters);

        foreach ($filters as $key => $filter)
        {
            $filters[$key] = '(' . str_replace('\3b', ';', $filter) . ')';
        }

        return $filters;
    }

    /**
     * Gets the group ids to which the user should be assigned.
     *
     * @param   User    $user   the user object
     * @param   string  $email  the email value returned by the query
     *
     * @return array the ids to which the user should be assigned
     */
    private function getGroupIDs(array $result, User $user, string $email): array
    {
        /** @var Registry $params */
        $params   = $this->params;
        $groupIDs = [];

        // Futureproof group id assignment by ensuring that the id is always the same as the value.

        // Keeps existing assignments
        if ($user->id)
        {
            foreach ($user->groups as $groupID)
            {
                $groupIDs[$groupID] = $groupID;
            }
        }

        // If there are no rules we're done.
        if (!$rules = $params->get('rules'))
        {
            return $groupIDs;
        }

        $emails     = (string) $params->get('emails');
        $emails     = empty($result[$emails]) ? [$email] : $result[$emails];
        $ldapGroups = (string) $params->get('ldap_groups');
        $ldapGroups = empty($result[$ldapGroups]) ? [] : $result[$ldapGroups];

        foreach ($rules as $rule)
        {
            // The rule does not contain a group assignment => invalid and hopefully impossible
            if (!$groupID = (int) $rule->groupID)
            {
                continue;
            }

            // The rule restricts ldap groups
            if ($ruleGroups = array_filter(explode(',', str_replace(' ', '', $rule->ldap_group))))
            {
                if (!$ldapGroups or !array_intersect($ruleGroups, $ldapGroups))
                {
                    // No group assignment or no relevant group assignment
                    continue;
                }
            }

            // The rule restricts subdomains
            if ($subDomains = array_filter(explode(',', str_replace(' ', '', $rule->subdomain))))
            {
                if (!$this->checkSDRelevance($emails, $subDomains))
                {
                    // No relevant subdomain found among the user's email addresses
                    continue;
                }
            }

            $groupIDs[$groupID] = $groupID;
        }

        return $groupIDs;
    }

    /**
     * Maps the user id to the relevant group ids.
     *
     * @param   int    $userID    the user id
     * @param   array  $groupIDs  the group ids
     *
     * @return void
     */
    private function mapGroupIDs(int $userID, array $groupIDs): void
    {
        $db       = $this->db;
        $map      = $db->quoteName('#__user_usergroup_map');
        $mGroupID = $db->quoteName('group_id');
        $mUserID  = $db->quoteName('user_id');

        foreach ($groupIDs as $groupID)
        {
            // Skip existing user -> user group assignments.
            $query = $db->getQuery(true);
            $query->select('*')->from($map)->where("$mUserID = $userID")->where("$mGroupID = $groupID");
            $db->setQuery($query);

            if ($db->loadAssoc())
            {
                continue;
            }

            $query = $db->getQuery(true);
            $query->insert($map)->columns([$mGroupID, $mUserID])->values("$groupID, $userID");
            $db->setQuery($query);
            $db->execute();
        }

        $groupIDs = implode(',', $groupIDs);
        $query    = $db->getQuery(true);
        $query->delete($map)->where("$mUserID = $userID")->where("$mGroupID NOT IN ($groupIDs)");
        $db->setQuery($query);
        $db->execute();
    }

    /**
     * Authenticates a user and maps it into specifically configured groups or the configured default group.
     *
     * @param   array                   $credentials  Array holding the user credentials
     * @param   array                   $options      Array of extra options
     * @param   AuthenticationResponse  $response     the response to the authentication event
     *
     * @return  void success is stored in the response->status
     * @noinspection PhpUnusedParameterInspection
     * @throws Exception
     */
    public function onUserAuthenticate(array $credentials, array $options, AuthenticationResponse $response): void
    {
        /** @var Registry $params */
        $params         = $this->params;
        $this->override = (bool) $params->get('override');
        $response->type = 'LDAP';

        // Error messaging performed on the AuthenticationResponse object.
        if (!$this->validateCredentials($credentials, $response))
        {
            return;
        }

        // Error messaging performed on the AuthenticationResponse object.
        if (!$this->validateConfiguration($response))
        {
            return;
        }

        // User not found, allow Joomla to continue with no messaging
        if (!$result = $this->search($credentials, $response))
        {
            return;
        }

        if (empty($result[$this->emailAttribute]) or empty($result[$this->nameAttribute]))
        {
            $response->status        = Authentication::STATUS_FAILURE;
            $response->error_message = Text::_('MAPPED_LDAP_ATTRIBUTE_CONFIGURATION_INVALID');

            return;
        }

        $email    = reset($result[$this->emailAttribute]);
        $name     = reset($result[$this->nameAttribute]);
        $rules    = $params->get('rules');
        $userName = $credentials['username'];
        $user     = User::getInstance($userName);
        $new      = empty($user->id);

        // The search was successful and no mapping can take place
        if (!$rules)
        {
            $response->email         = $email;
            $response->error_message = '';
            $response->fullname      = $name;
            $response->status        = Authentication::STATUS_SUCCESS;
            $response->username      = $userName;

            return;
        }

        if ($new)
        {
            $user->email    = $email;
            $user->name     = $name;
            $user->username = $userName;
        }

        // No configured groups were applicable.
        if (!$groupIDs = $this->getGroupIDs($result, $user, $email))
        {
            // Override Joomla's handling by not authenticating.
            if ($new and $this->override)
            {
                $response->status        = Authentication::STATUS_FAILURE;
                $response->error_message = Text::_('MAPPED_LDAP_NO_APPLICABLE_RULES');

                return;
            }

            // Joomla will take care of the default group on its own.
            $response->email         = $email;
            $response->error_message = '';
            $response->fullname      = $name;
            $response->status        = Authentication::STATUS_SUCCESS;
            $response->username      = $userName;

            return;
        }

        // Create a new user to map with
        if ($new)
        {
            if (!$this->override)
            {
                $defaultID            = ComponentHelper::getParams('com_users')->get('new_usertype');
                $groupIDs[$defaultID] = $defaultID;
            }

            $saved = false;
            foreach ($groupIDs as $groupID)
            {
                if (Access::checkGroup($groupID, 'core.manage'))
                {
                    $user->groups[$groupID] = $groupID;

                    if ($user->save())
                    {
                        $saved = true;
                        break;
                    }

                    $response->status        = Authentication::STATUS_FAILURE;
                    $response->error_message = Text::_('MAPPED_LDAP_NEW_USER_NOT_SAVED');

                    return;
                }
            }

            if (!$saved)
            {
                $defaultID                = reset($groupIDs);
                $user->groups[$defaultID] = $defaultID;

                if (!$user->save())
                {
                    $response->status        = Authentication::STATUS_FAILURE;
                    $response->error_message = Text::_('MAPPED_LDAP_NEW_USER_NOT_SAVED');

                    return;
                }
            }
        }

        $this->mapGroupIDs($user->id, $groupIDs);

        $response->email         = $email;
        $response->error_message = '';
        $response->fullname      = $name;
        $response->status        = Authentication::STATUS_SUCCESS;
        $response->username      = $userName;
    }

    /**
     * Searches for the user by querying the LDAP server.
     *
     * @param   array                   $credentials  the username and password entered by the user
     * @param   AuthenticationResponse  $response     the response to the authentication event
     *
     * @return array
     */
    private function search(array $credentials, AuthenticationResponse $response): array
    {
        if (!$this->connect($response))
        {
            return [];
        }

        $filters  = $this->getFilters($credentials);
        $userName = $credentials['username'];
        $result   = [];
        $success  = false;

        switch ($this->method)
        {
            case self::SEARCH:

                if ($this->bind())
                {
                    $result = $this->query($filters);

                    if (!$result or empty($result['dn']))
                    {
                        $response->status        = Authentication::STATUS_FAILURE;
                        $response->error_message = Text::_('MAPPED_LDAP_USERNAME_INVALID');
                    }
                    elseif (!$success = $this->bind($result['dn'], $credentials['password'], true))
                    {
                        $response->status        = Authentication::STATUS_FAILURE;
                        $response->error_message = Text::_('MAPPED_LDAP_PASSWORD_INVALID');
                    }
                }

                break;

            case self::DIRECT:

                $dnUN = ldap_escape($userName, null, LDAP_ESCAPE_DN);

                if ($success = $this->bind($dnUN, $credentials['password']))
                {
                    $result = $this->query($filters);

                    if (!$result or empty($result['dn']))
                    {
                        $response->status        = Authentication::STATUS_FAILURE;
                        $response->error_message = Text::_('MAPPED_LDAP_USER_DATA_INCONSISTENT');
                    }
                }
                else
                {
                    $response->status        = Authentication::STATUS_FAILURE;
                    $response->error_message = Text::_('MAPPED_LDAP_PASSWORD_INVALID');
                }

                break;
        }

        $success = ($success and $this->unbind($response));

        return ($success and $result) ? $result : [];
    }

    /**
     * Perform an LDAP search
     *
     * @param   string[]  $filters  search filters
     *
     * @return  array  search results
     */
    public function query(array $filters): array
    {
        // Required by signature, but unused
        $dummy    = [];
        $resource = $this->connection;
        $results  = [];

        foreach ($filters as $filter)
        {
            if (!$initialResult = ldap_search($resource, $this->baseFilter, $filter, $dummy))
            {
                continue;
            }
            elseif (!$count = ldap_count_entries($resource, $initialResult))
            {
                continue;
            }

            $nextResult = null;

            for ($index = 0; $index < $count; $index++)
            {
                $results[$index] = [];

                $nextResult = $index ? ldap_next_entry($resource, $nextResult) : ldap_first_entry($resource, $initialResult);

                // Load user-specified attributes
                $attributes = ldap_get_attributes($this->connection, $nextResult);

                /**
                 * $attributes = [
                 *      attribute name => ['count' => # of values, index => value, ...], OR
                 *      # => the previous attribute name, OR
                 *      count => the number of attributes
                 * ]
                 */
                foreach ($attributes as $aName => $aValues)
                {
                    // An actual name => values pair
                    if (is_array($aValues))
                    {
                        $results[$index][$aName] = [];

                        for ($valuesKey = 0; $valuesKey < $aValues['count']; $valuesKey++)
                        {
                            $results[$index][$aName][$valuesKey] = $aValues[$valuesKey];
                        }
                    }
                }

                $results[$index]['dn'] = ldap_get_dn($this->connection, $nextResult);
            }
        }

        return $results ? reset($results) : $results;
    }

    /**
     * Unbinds from the LDAP directory
     *
     * @param   AuthenticationResponse|null  $response  the response if available, used for messaging
     *
     * @return  bool
     */
    public function unbind(AuthenticationResponse $response = null): bool
    {
        if (!ldap_unbind($this->connection))
        {
            if ($response)
            {
                $response->status        = Authentication::STATUS_FAILURE;
                $response->error_message = Text::_('MAPPED_LDAP_RESOURCE_RELEASE_FAILED');
            }

            return false;
        }

        return true;
    }

    /**
     * Validates the plugin configuration.
     *
     * @param   AuthenticationResponse  $response  the response to the authentication event
     *
     * @return bool
     */
    private function validateConfiguration(AuthenticationResponse $response): bool
    {
        /** @var Registry $parameters */
        $parameters = $this->params;

        $this->allowReferrals = !((int) $parameters->get('no_referrals') === 0);

        if (!$this->emailAttribute = (string) $parameters->get('email'))
        {
            $response->status        = Authentication::STATUS_FAILURE;
            $response->error_message = Text::_('MAPPED_LDAP_EMAIL_ATTRIBUTE_MISSING');

            return false;
        }

        if (!$this->host = (string) $parameters->get('host'))
        {
            $response->status        = Authentication::STATUS_FAILURE;
            $response->error_message = Text::_('MAPPED_LDAP_HOST_MISSING');

            return false;
        }

        $this->method = (int) $parameters->get('method') === 1 ? 1 : 0;

        if (!$this->nameAttribute = (string) $parameters->get('name'))
        {
            $response->status        = Authentication::STATUS_FAILURE;
            $response->error_message = Text::_('MAPPED_LDAP_NAME_ATTRIBUTE_MISSING');

            return false;
        }

        if (!$this->port = (int) $parameters->get('port'))
        {
            $response->status        = Authentication::STATUS_FAILURE;
            $response->error_message = Text::_('MAPPED_LDAP_PORT_MISSING');

            return false;
        }

        if (!$this->query = (string) $parameters->get('search'))
        {
            $response->status        = Authentication::STATUS_FAILURE;
            $response->error_message = Text::_('MAPPED_LDAP_QUERY_MISSING');

            return false;
        }

        if (!$this->userName = (string) $parameters->get('username'))
        {
            $response->status        = Authentication::STATUS_FAILURE;
            $response->error_message = Text::_('MAPPED_LDAP_USERNAME_MISSING');

            return false;
        }

        if (!$this->userPassword = (string) $parameters->get('password'))
        {
            $response->status        = Authentication::STATUS_FAILURE;
            $response->error_message = Text::_('MAPPED_LDAP_PASSWORD_MISSING');

            return false;
        }

        // The plugin is in charge but has no way to assign groups
        if ($this->override and !$parameters->get('rules'))
        {
            $response->status        = Authentication::STATUS_FAILURE;
            $response->error_message = Text::_('MAPPED_LDAP_MAPPING_CONFIGURATION_INVALID');

            return false;
        }

        /**
         * Distinguished Name (DN) Configuration
         * c:       country name
         * cn:      common name
         * dc:      domain component
         * l:       locality name
         * o:       organization name
         * ou:      organized unit name
         * street:  street address
         * st:      state or province name
         * uid:     user id
         */
        $dns = "(cn|c|dc|l|o|ou|st|street|uid)";

        /**
         * TODO expand the pattern for other punctuation marks and escaped characters
         * https://datatracker.ietf.org/doc/html/rfc4514
         */
        $value  = "(\d|\w|-)+";
        $clause = "$dns=$value";

        $pattern = "/^($clause,)*$clause$/i";
        if (!$this->baseFilter = (string) $parameters->get('base_dn'))
        {
            $response->status        = Authentication::STATUS_FAILURE;
            $response->error_message = Text::_('MAPPED_LDAP_BASE_DNS_MISSING');

            return false;
        }
        elseif (preg_match($pattern, $this->baseFilter) !== 1)
        {
            $response->status        = Authentication::STATUS_FAILURE;
            $response->error_message = Text::_('MAPPED_LDAP_BASE_DNS_INVALID');

            return false;
        }

        $pattern = "/^($clause,)*$clause(;$clause(,$clause)*)?$/i";
        if (!$this->usersFilter = $parameters->get('users_dn'))
        {
            $response->status        = Authentication::STATUS_FAILURE;
            $response->error_message = Text::_('MAPPED_LDAP_USER_DNS_MISSING');

            return false;
        }
        elseif (preg_match($pattern, $this->usersFilter) !== 1)
        {
            $response->status        = Authentication::STATUS_FAILURE;
            $response->error_message = Text::_('MAPPED_LDAP_USER_DNS_INVALID');

            return false;
        }

        return true;
    }

    /**
     * Validates the given credentials for plausibility. Actual validation is of course performed on the LDAP server. ;)
     *
     * @param   array                   $credentials  the username and password entered by the user
     * @param   AuthenticationResponse  $response     the response to the authentication event
     *
     * @return bool
     */
    private function validateCredentials(array &$credentials, AuthenticationResponse $response): bool
    {
        // Strip null bytes from the password
        $credentials['password'] = str_replace(chr(0), '', $credentials['password']);

        if (empty($credentials['password']))
        {
            $response->status        = Authentication::STATUS_FAILURE;
            $response->error_message = Text::_('MAPPED_LDAP_EMPTY_PASSWORD');

            return false;
        }

        // Account exists
        if (UserHelper::getUserId($credentials['username']))
        {
            return true;
        }

        $params     = $this->params;
        $userParams = ComponentHelper::getParams('com_users');

        // The site allows registration and has a group configured
        if ($userParams->get('allowUserRegistration'))
        {
            return true;
        }
        // The plugin supersedes user settings there is at least one mappable group
        elseif ($this->override and $params->get('rules'))
        {
            return true;
        }

        $response->status        = Authentication::STATUS_FAILURE;
        $response->error_message = Text::_('MAPPED_LDAP_USER_NOT_REGISTERED');

        return false;
    }
}
