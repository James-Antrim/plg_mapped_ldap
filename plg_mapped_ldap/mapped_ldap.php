<?php
/** @noinspection PhpClassNamingConventionInspection */
/** @noinspection PhpDeprecationInspection */
/**
 * @package     Mapped LDAP
 * @extension   plg_mapped_ldap
 * @author      James Antrim, <james.antrim@nm.thm.de>
 * @copyright   2021 TH Mittelhessen
 * @license     GNU GPL v.3
 * @link        www.thm.de
 */

defined('_JEXEC') or die;

use Joomla\CMS\Authentication\Authentication;
use Joomla\CMS\Authentication\AuthenticationResponse;
use Joomla\CMS\Component\ComponentHelper;
use Joomla\CMS\Factory;
use Joomla\CMS\Language\Text;
use Joomla\CMS\User\User;
use Joomla\CMS\User\UserHelper;
use Joomla\Registry\Registry;

/**
 * Mapped LDAP Authentication Plugin
 */
class PlgAuthenticationMapped_LDAP extends JPlugin
{
	private const DIRECT = 1, SEARCH = 0;

	public string $accountName;

	private string $accountPassword = '';

	public bool $allowReferrals = true;

	private bool $bound = false;

	private string $domain = '';

	private string $directoryDomains = '';

	public string $host = '';

	private int $method = 0;

	private int $port = 0;

	/**
	 * LDAP Resource Identifier
	 *
	 * @var    resource|null
	 * @since  1.0
	 */
	private $resource = null;

	private string $serverDomains = '';

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
	 * @param   string  $username  The username
	 * @param   string  $password  The password
	 * @param   string  $nosub     ...
	 *
	 * @return  boolean
	 *
	 * @since   1.0
	 */
	public function bind(AuthenticationResponse $response, string $username = '', string $password = '', int $nosub = 0): bool
	{
		if (!$this->resource)
		{
			if (!$this->connect($response))
			{
				return false;
			}
		}

		$username = $username ?: $this->accountName;
		$password = $password ?: $this->accountPassword;

		if (!$this->users_dn or $useUsername)
		{
			$this->domain = $username;
		}
		elseif (strlen($username))
		{
			$this->domain = str_replace('[username]', $username, $this->users_dn);
		}
		else
		{
			$this->domain = '';
		}

		$this->bound = ldap_bind($this->resource, $this->domain, $password);

		return $this->bound;
	}

	/**
	 * Connect to an LDAP server
	 *
	 * @return  boolean
	 *
	 * @since   1.0
	 */
	private function connect(AuthenticationResponse $response): bool
	{
		if (!$this->resource = ldap_connect($this->host, $this->port))
		{
			$response->status        = Authentication::STATUS_FAILURE;
			$response->error_message = Text::_('MAPPED_LDAP_CONNECTION_FAILEDxxx');

			return false;
		}

		// Other versions no longer supported => parameter check removed
		if (!ldap_set_option($this->resource, LDAP_OPT_PROTOCOL_VERSION, 3))
		{
			$response->status        = Authentication::STATUS_FAILURE;
			$response->error_message = Text::_('MAPPED_LDAP_OPT_PROTOCOL_VERSION_FAILEDxxx');

			return false;
		}

		if (!ldap_set_option($this->resource, LDAP_OPT_REFERRALS, $this->allowReferrals))
		{
			$response->status        = Authentication::STATUS_FAILURE;
			$response->error_message = Text::_('MAPPED_LDAP_OPT_REFERRALS_FAILEDxxx');

			return false;
		}

		// Apparently insecure without TLS => parameter check removed
		if (!ldap_start_tls($this->resource))
		{
			$response->status        = Authentication::STATUS_FAILURE;
			$response->error_message = Text::_('MAPPED_LDAP_TLS_NEGOTIATION_FAILEDxxx');

			return false;
		}

		return true;
	}

	/**
	 * Authenticates a user and maps it into specifically configured groups or the configured default group.
	 *
	 * @param   array                   $credentials  Array holding the user credentials
	 * @param   array                   $options      Array of extra options
	 * @param   AuthenticationResponse  $response     AuthenticationResponse object
	 *
	 * @return  void success is stored in the response->status
	 * @noinspection PhpUnusedParameterInspection
	 * @throws Exception
	 */
	public function onUserAuthenticate(array $credentials, array $options, AuthenticationResponse $response)
	{
		$response->type = 'LDAP';
		$this->loadLanguage();

		/**
		 * Removed params:
		 * ignore_reqcert_tls   wasn't used to begin with
		 * ldap_debug           wasn't used to begin with
		 * negotiate_tls        always true, completely removed
		 * use_ldapV3           always true, completely removed
		 */

		if (!$this->validateConfiguration($response))
		{
			// Messaging performed on the AuthenticationResponse object.
			return;
		}

		if (!$this->validateCredentials($credentials, $response))
		{
			// Messaging performed on the AuthenticationResponse object.
			return;
		}

		/** @var Registry $params */
		$params = $this->params;
		$method = $this->method;

		if (!$this->connect($response))
		{
			return;
		}

		$message  = '';
		$userName = $credentials['username'];
		$result   = [];
		$search   = str_replace(
			'[search]',
			str_replace(';', '\3b', ldap_escape($userName, null, LDAP_ESCAPE_FILTER)),
			$params->get('search')
		);
		$success  = false;

		switch ($method)
		{
			case self::SEARCH:

				// Without altering the client, this parameter cannot be change to be more appropriate.
				$bound = $this->bind($response);

				if ($bound)
				{
					$result = $this->search($client, $search);

					if (empty($result) or empty($result['dn']) or !$success = $client->bind($result['dn'],
							$credentials['password'], 1))
					{
						$message = Text::_('JGLOBAL_AUTH_NO_USER');
					}
				}
				else
				{
					$message = Text::_('JGLOBAL_AUTH_NOT_CONNECT');
				}

				break;

			case self::DIRECT:

				// We just accept the result here
				if ($success = $this->bind($response, ldap_escape($userName, null, LDAP_ESCAPE_DN), $credentials['password']))
				{
					$result = $this->search($client, $search);
				}
				else
				{
					$message = Text::_('JGLOBAL_AUTH_INVALID_PASS');
				}

				break;
		}

		$this->unbind();

		// Authentication was not successful.
		if (!$success or empty($result))
		{
			$response->status        = Authentication::STATUS_FAILURE;
			$response->error_message = $message ?: Text::_('JGLOBAL_AUTH_INVALID_PASS');

			return;
		}

		$email = (string) $params->get('email');
		$name  = (string) $params->get('name');

		if (empty($result[$email]) or empty($result[$name]))
		{
			$response->status        = Authentication::STATUS_FAILURE;
			$response->error_message = Text::_('JGLOBAL_AUTH_USER_NOT_FOUND');

			return;
		}

		$email    = reset($result[$email]);
		$name     = reset($result[$name]);
		$override = (bool) $params->get('override');
		$rules    = $params->get('rules');
		$user     = User::getInstance($userName);

		if (!$user->id)
		{
			// Override: no rules, no authentication for new users.
			if ($override and !$rules)
			{
				$response->status        = Authentication::STATUS_FAILURE;
				$response->error_message = $message ?: Text::_('MAPPED_LDAP_NO_RULES');

				return;
			}

			$user->email    = $email;
			$user->name     = $name;
			$user->username = $userName;
		}
		// The user exists and there are no rules to assign them more groups.
		elseif (!$rules)
		{
			$response->email         = $email;
			$response->error_message = '';
			$response->fullname      = $name;
			$response->status        = Authentication::STATUS_SUCCESS;
			$response->username      = $userName;

			return;
		}

		$domain             = (string) $params->get('domain');
		$emails             = (string) $params->get('emails');
		$emails             = empty($result[$emails]) ? [$email] : $result[$emails];
		$assignedLDAPGroups = (string) $params->get('ldap_groups');
		$assignedLDAPGroups = empty($result[$assignedLDAPGroups]) ? [] : $result[$assignedLDAPGroups];

		$existingGroupIDs = $user->groups;
		$groupIDs         = [];

		// Futureproof group id assignment by ensuring that the id is always the same as the value.
		foreach ($existingGroupIDs as $groupID)
		{
			$groupIDs[$groupID] = $groupID;
		}

		foreach ($rules as $rule)
		{
			// The rule does not contain a group assignment => invalid.
			if (!$groupID = (int) $rule->groupID)
			{
				continue;
			}

			// Avoid running trim on individual array items
			$ruleGroups = str_replace(' ', '', $rule->ldap_group);
			$ruleGroups = explode(',', $ruleGroups);
			$subDomains = str_replace(' ', '', $rule->subdomain);
			$subDomains = explode(',', $subDomains);

			// The rule restricts groups and the person is either not assigned a group or not assigned a relevant group.
			if ($ruleGroups and (!$assignedLDAPGroups or !array_intersect($ruleGroups, $assignedLDAPGroups)))
			{
				continue;
			}

			// Check for subdomain relevance
			if ($subDomains)
			{
				$relevant = false;

				foreach ($subDomains as $subDomain)
				{
					// Email was already assigned => variable name safe.
					foreach ($emails as $email)
					{
						$pieces = explode('@', $email);

						// Invalid or irrelevant
						if (!$emailDomain = array_pop($pieces) or strpos($emailDomain, ".$domain") === false)
						{
							continue;
						}

						if (str_replace(".$domain", '', $emailDomain) === $subDomain)
						{
							$relevant = true;
							break 2;
						}
					}
				}

				if (!$relevant)
				{
					continue;
				}
			}

			$groupIDs[$groupID] = $groupID;
		}

		if (!$groupIDs)
		{
			// Override Joomla's handling by not authenticating.
			if ($override and !$user->id)
			{
				$response->status        = Authentication::STATUS_FAILURE;
				$response->error_message = Text::_('MAPPED_LDAP_NO_APPLICABLE_RULES');

				return;
			}

			// Let Joomla do its thing.
			$response->email         = $email;
			$response->error_message = '';
			$response->fullname      = $name;
			$response->status        = Authentication::STATUS_SUCCESS;
			$response->username      = $userName;

			return;
		}

		$new = false;

		// Create a new user with the default group id
		if (empty($user->id))
		{
			$defaultID = ComponentHelper::getParams('com_users')->get('new_usertype');
			$new       = true;

			$user->groups[$defaultID] = $defaultID;
			$user->save();
		}

		// Joomla internal problems
		if (empty($user->id))
		{
			$response->status        = Authentication::STATUS_FAILURE;
			$response->error_message = $message ?: Text::_('JERROR_AN_ERROR_HAS_OCCURRED');

			return;
		}

		$dbo = Factory::getDbo();

		foreach ($groupIDs as $groupID)
		{
			// Skip existing user -> user group assignments.
			if (!$new)
			{
				$query = $dbo->getQuery(true);
				$query->select('*')->from('#__user_usergroup_map')->where("user_id = $user->id")->where("group_id = $groupID");
				$dbo->setQuery($query);
				$row = $dbo->loadAssoc();

				if ($row)
				{
					continue;
				}
			}

			$query = $dbo->getQuery(true);
			$query->insert('#__user_usergroup_map')->columns('group_id, user_id')->values("$groupID, $user->id");
			$dbo->setQuery($query);
			$dbo->execute();
		}

		$groupIDs = implode(',', $groupIDs);
		$query    = $dbo->getQuery(true);
		$query->delete('#__user_usergroup_map')->where("user_id = $user->id")->where("group_id NOT IN ($groupIDs)");
		$dbo->setQuery($query);
		$dbo->execute();

		$response->email         = $email;
		$response->error_message = '';
		$response->fullname      = $name;
		$response->status        = Authentication::STATUS_SUCCESS;
		$response->username      = $userName;
	}

	/**
	 * Builds a search string based on semicolon separated items. Calls the client search function. Returns the first
	 * result.
	 *
	 * @param   LDAPClient  $client  the LDAP client
	 * @param   string      $search  search string of search values
	 *
	 * @return  array  Search result (singular)
	 */
	private function search(Client $client, string $search): array
	{
		$results = explode(';', $search);

		foreach ($results as $key => $result)
		{
			$results[$key] = '(' . str_replace('\3b', ';', $result) . ')';
		}

		$results = $client->search($results);

		return reset($results) ?: [];
	}

	/**
	 * Perform an LDAP search
	 *
	 * @param   array   $filters     Search Filters (array of strings)
	 * @param   string  $dnoverride  DN Override
	 * @param   array   $attributes  An array of attributes to return (if empty, all fields are returned).
	 *
	 * @return  array  Multidimensional array of results
	 */
	public function searchToo(array $filters, $dnoverride = null, array $attributes = [])
	{
		$result = [];

		if (!$this->bound || !$this->resource)
		{
			return $result;
		}

		if ($dnoverride)
		{
			$dn = $dnoverride;
		}
		else
		{
			$dn = $this->baseDomains;
		}

		foreach ($filters as $searchFilter)
		{
			$searchResult = ldap_search($this->resource, $dn, $searchFilter, $attributes);

			if ($searchResult && ($count = ldap_count_entries($this->resource, $searchResult)) > 0)
			{
				for ($i = 0; $i < $count; $i++)
				{
					$result[$i] = [];

					if (!$i)
					{
						$firstentry = ldap_first_entry($this->resource, $searchResult);
					}
					else
					{
						$firstentry = ldap_next_entry($this->resource, $firstentry);
					}

					// Load user-specified attributes
					$attributeResult = ldap_get_attributes($this->resource, $firstentry);

					// LDAP returns an array of arrays, fit this into attributes result array
					foreach ($attributeResult as $ki => $ai)
					{
						if (is_array($ai))
						{
							$subcount        = $ai['count'];
							$result[$i][$ki] = [];

							for ($k = 0; $k < $subcount; $k++)
							{
								$result[$i][$ki][$k] = $ai[$k];
							}
						}
					}

					$result[$i]['dn'] = ldap_get_dn($this->resource, $firstentry);
				}
			}
		}

		return $result;
	}

	/**
	 * Unbinds from the LDAP directory
	 *
	 * @return  bool
	 */
	public function unbind(): bool
	{
		if ($this->resource)
		{
			$unbound        = ldap_unbind($this->resource);
			$this->resource = null;

			return $unbound;
		}

		return true;
	}

	/**
	 * Validates the plugin configuration.
	 *
	 * @param   AuthenticationResponse  $response
	 *
	 * @return bool
	 */
	private function validateConfiguration(AuthenticationResponse $response): bool
	{
		/** @var Registry $parameters */
		$parameters = $this->params;

		if (!$this->accountName = (string) $parameters->get('username'))
		{
			$response->status        = Authentication::STATUS_FAILURE;
			$response->error_message = Text::_('MAPPED_LDAP_USERNAME_MISSINGxxx');

			return false;
		}

		if (!$this->accountPassword = (string) $parameters->get('password'))
		{
			$response->status        = Authentication::STATUS_FAILURE;
			$response->error_message = Text::_('MAPPED_LDAP_PASSWORD_MISSINGxxx');

			return false;
		}

		$this->allowReferrals = !((int) $parameters->get('no_referrals') === 0);

		if (!$this->host = (string) $parameters->get('host'))
		{
			$response->status        = Authentication::STATUS_FAILURE;
			$response->error_message = Text::_('MAPPED_LDAP_HOST_MISSINGxxx');

			return false;
		}

		$this->method = (int) $parameters->get('method') === 1 ? 1 : 0;

		if (!$this->port = (int) $parameters->get('port'))
		{
			$response->status        = Authentication::STATUS_FAILURE;
			$response->error_message = Text::_('MAPPED_LDAP_PORT_MISSINGxxx');

			return false;
		}

		$pattern = '/^([\w\d\-]+=[\w\d\-]+,)*[\w\d\-]+=[\w\d\-]+$/';
		if (!$this->serverDomains = (string) $parameters->get('base_dn'))
		{
			$response->status        = Authentication::STATUS_FAILURE;
			$response->error_message = Text::_('MAPPED_LDAP_BASE_DOMAINS_MISSINGxxx');

			return false;
		}
		elseif (preg_match($pattern, $this->serverDomains) !== 1)
		{
			$response->status        = Authentication::STATUS_FAILURE;
			$response->error_message = Text::_('MAPPED_LDAP_BASE_DOMAINS_INVALIDxxx');

			return false;
		}

		$pattern = '/^([\w\d\-]+=[\w\d\-]+,)*[\w\d\-]+=[\w\d\-]+(;[\w\d\-]+=[\w\d\-]+(,[\w\d\-]+=[\w\d\-]+)*)?$/';
		if (!$this->directoryDomains = $parameters->get('users_dn'))
		{
			$response->status        = Authentication::STATUS_FAILURE;
			$response->error_message = Text::_('MAPPED_LDAP_USER_DOMAINS_MISSINGxxx');

			return false;
		}
		elseif (preg_match($pattern, $this->directoryDomains) !== 1)
		{
			$response->status        = Authentication::STATUS_FAILURE;
			$response->error_message = Text::_('MAPPED_LDAP_USER_DOMAINS_INVALIDxxx');

			return false;
		}

		return true;
	}

	/**
	 * Validates the given credentials for plausibility. Actual validation is of course performed on the LDAP server. ;)
	 *
	 * @param   array                   $credentials
	 * @param   AuthenticationResponse  $response
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
			$response->error_message = Text::_('MAPPED_LDAP_EMPTY_PASSWORDxxx');

			return false;
		}

		$userParams = ComponentHelper::getParams('com_users');

		// If the site configuration does not allow for user registration check for a matching username.
		if ($userParams->get('allowUserRegistration'))
		{
			return true;
		}

		if (UserHelper::getUserId($credentials['username']))
		{
			return true;
		}

		$response->status        = Authentication::STATUS_FAILURE;
		$response->error_message = Text::_('MAPPED_LDAP_USER_NOT_REGISTEREDxxx');

		return false;
	}
}
